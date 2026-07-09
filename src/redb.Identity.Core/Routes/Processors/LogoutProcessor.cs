using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;
using redb.Core;
using redb.Identity.Core.Models;
using redb.Identity.Core.Module;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.RedbCore.Extensions;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// Logout processor: extracts userId from body/session cookie, validates optional
/// <c>id_token_hint</c> (OIDC RP-Initiated Logout), and revokes sessions via SessionService.
/// </summary>
internal sealed class LogoutProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;
    private readonly ILogger? _logger;
    private readonly IOptionsMonitor<OpenIddictServerOptions> _serverOptions;
    private static readonly JsonWebTokenHandler _tokenHandler = new();

    public LogoutProcessor(
        IRouteContext context,
        IOptionsMonitor<OpenIddictServerOptions> serverOptions,
        string? redbName = null,
        ILogger? logger = null)
    {
        _context = context;
        _serverOptions = serverOptions;
        _redbName = redbName;
        _logger = logger;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var redb = _context.GetRedbService(_redbName, exchange);
        long userId = 0;
        long sessionId = 0;
        string? idTokenHint = null;

        // Canonical key name: "userId" — from body (POST form / JSON)
        if (exchange.In.Body is Dictionary<string, object?> dict)
        {
            userId = IdentityProcessorHelpers.ExtractLong(dict, "userId") ?? 0;
            if (dict.TryGetValue("id_token_hint", out var tokenHintObj))
                idTokenHint = tokenHintObj?.ToString();
        }
        else if (exchange.In.Body is Dictionary<string, string> sdict)
        {
            if (sdict.TryGetValue("userId", out var s1)) long.TryParse(s1, out userId);
            sdict.TryGetValue("id_token_hint", out idTokenHint);
        }

        // Extract sessionId from cookie header (set by ReadSessionCookie)
        if (exchange.In.Headers.TryGetValue("session_id", out var rawSid))
        {
            if (rawSid is long sidLong) sessionId = sidLong;
            else if (rawSid is string sidStr) long.TryParse(sidStr, out sessionId);
        }

        // Fallback: extract userId from session cookie headers (set by ReadSessionCookie)
        if (userId <= 0 && exchange.In.Headers.TryGetValue("session_user_id", out var rawId))
        {
            if (rawId is long sid) userId = sid;
            else if (rawId is string sidStr) long.TryParse(sidStr, out userId);
        }

        if (userId <= 0)
        {
            IdentityProcessorHelpers.SetError(exchange, "invalid_request",
                "userId is required for logout (provide in body or via session cookie)");
            return;
        }

        // OIDC RP-Initiated Logout: process id_token_hint if present
        if (!string.IsNullOrEmpty(idTokenHint))
        {
            var (hintSub, hintAud) = await ValidateIdTokenHintAsync(idTokenHint);

            if (hintSub is null)
            {
                // Signature invalid or missing sub — treat as no hint (already logged inside)
            }
            else if (hintSub != userId.ToString())
            {
                // OIDC RP-Initiated Logout §2: sub mismatch → MUST treat as if hint not provided
                _logger?.LogWarning(
                    "id_token_hint sub '{HintSub}' does not match session user {UserId} — ignoring hint",
                    hintSub, userId);
            }
            else
            {
                // Valid hint, sub matches — safe to use aud for post_logout_redirect_uri scoping
                if (hintAud is not null)
                    exchange.Properties["logout_client_id"] = hintAud;
            }
        }

        var session = new SessionService(redb);
        int sessionsRevoked;

        // Collect distinct ApplicationObjectIds BEFORE revocation, so we know which RPs to
        // notify via Backchannel Logout 1.0. After revocation we'd still see them, but doing
        // it up-front keeps the dispatch payload deterministic.
        var affectedApplicationIds = await CollectAffectedApplicationIdsAsync(redb, userId, sessionId, ct);

        if (sessionId > 0)
        {
            // Per-session logout: revoke only the current session + its authorizations
            sessionsRevoked = await session.RevokeAsync(sessionId, ct);
        }
        else
        {
            // Fallback: nuclear logout (revoke all sessions + all authorizations)
            sessionsRevoked = await session.LogoutAsync(userId, ct);
        }

        // Best-effort backchannel logout fan-out. Failures are logged but never break logout.
        // BackchannelLogoutDispatcher is registered in the Identity child container — resolve
        // through the IRouteContext scope helper, NOT exchange.ServiceProvider (that's the
        // *host* container, where the dispatcher is not registered).
        var dispatcher = _context.GetIdentityServiceOrDefault<BackchannelLogoutDispatcher>(exchange);
        int backchannelDelivered = 0;
        if (dispatcher is not null && affectedApplicationIds.Count > 0)
        {
            try
            {
                backchannelDelivered = await dispatcher.DispatchAsync(
                    redb, userId, sessionId, affectedApplicationIds, ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "BackchannelLogoutDispatcher.DispatchAsync threw — logout flow continues.");
            }
        }

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new Dictionary<string, object?>
        {
            ["success"] = true,
            ["sessions_revoked"] = sessionsRevoked,
            ["backchannel_delivered"] = backchannelDelivered
        };
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.UserLoggedOut;
        exchange.Properties["identity-event-data"] = new
        {
            UserId = userId,
            SessionsRevoked = sessionsRevoked,
            BackchannelDelivered = backchannelDelivered,
            BackchannelTargets = affectedApplicationIds.Count
        };
    }

    /// <summary>
    /// Collects the distinct application object ids that are about to lose their session.
    /// For per-session logout: the single application linked to that session.
    /// For nuclear logout: union of every active session and every non-revoked authorization.
    /// </summary>
    private async Task<IReadOnlyCollection<long>> CollectAffectedApplicationIdsAsync(
        IRedbService redb, long userId, long sessionId, CancellationToken ct)
    {
        var ids = new HashSet<long>();

        if (sessionId > 0)
        {
            var s = await redb.LoadAsync<SessionProps>(sessionId).ConfigureAwait(false);
            if (s is not null && s.Props.ApplicationObjectId > 0 && s.Props.Status != "revoked")
                ids.Add(s.Props.ApplicationObjectId);
            return ids;
        }

        // Sessions use Key == userId (long).
        var sessions = await redb.Query<SessionProps>()
            .WhereRedb(o => o.Key == userId)
            .Where(p => p.Status == "active")
            .ToListAsync()
            .ConfigureAwait(false);
        foreach (var s in sessions)
            if (s.Props.ApplicationObjectId > 0)
                ids.Add(s.Props.ApplicationObjectId);

        // Authorizations and Tokens are written by OpenIddict stores via SetSubjectAsync
        // which writes the *public* GUID sub into _objects.value_guid (not Key). The GUID
        // lives on the UserProps "oidc" sibling object (Key == coreUser.Id), NOT on the
        // core-user object whose id is `userId`. Look it up by Key, then query auths/tokens
        // by ValueGuid.
        var userProps = await redb.Query<UserProps>()
            .WhereRedb(o => o.Key == userId)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);
        var subjectGuid = userProps?.value_guid ?? Guid.Empty;

        if (subjectGuid != Guid.Empty)
        {
            var auths = await redb.Query<AuthorizationProps>()
                .WhereRedb(o => o.ValueGuid == subjectGuid)
                .Where(p => p.Status != "revoked")
                .ToListAsync()
                .ConfigureAwait(false);
            foreach (var a in auths)
                if (a.Props.ApplicationObjectId > 0)
                    ids.Add(a.Props.ApplicationObjectId);

            // ROPC and other non-interactive grants emit access/refresh tokens without
            // creating an OpenIddict Authorization row, so the union above misses them.
            // Tokens always carry ApplicationObjectId; including their distinct apps
            // ensures Backchannel-Logout RFC fan-out covers every RP that holds a live
            // token for this user.
            var tokens = await redb.Query<TokenProps>()
                .WhereRedb(o => o.ValueGuid == subjectGuid)
                .Where(p => p.Status != "revoked")
                .ToListAsync()
                .ConfigureAwait(false);
            foreach (var t in tokens)
                if (t.Props.ApplicationObjectId > 0)
                    ids.Add(t.Props.ApplicationObjectId);
        }

        return ids;
    }

    /// <summary>
    /// Validates the id_token_hint JWT signature using our own signing keys and extracts
    /// <c>sub</c> and <c>aud</c> claims. Returns (null, null) if validation fails.
    /// </summary>
    private async Task<(string? sub, string? aud)> ValidateIdTokenHintAsync(string jwt)
    {
        try
        {
            var opts = _serverOptions.CurrentValue;
            var signingKeys = opts.SigningCredentials
                .Select(c => c.Key)
                .ToList();

            if (signingKeys.Count == 0)
            {
                _logger?.LogWarning("No signing keys configured — cannot validate id_token_hint");
                return (null, null);
            }

            // Microsoft.IdentityModel does STRICT-STRING issuer comparison — no URI
            // normalisation. OpenIddict mints id_tokens with iss=opts.Issuer.AbsoluteUri
            // which always carries a trailing slash (Uri normalises path "" → "/"). If we
            // pass only the TrimEnd('/') form here, validation fails with IDX10205
            // ("Issuer: 'http://host:5002/'. Did not match: ValidIssuer 'http://host:5002'")
            // on every logout that supplies an id_token_hint signed by ourselves. Accept
            // both forms so admin-configured Issuer values with/without a trailing slash
            // both work end-to-end.
            var issuerWithSlash = opts.Issuer?.ToString();
            var issuerNoSlash = issuerWithSlash?.TrimEnd('/');
            var validationParams = new TokenValidationParameters
            {
                ValidIssuers = opts.Issuer is null
                    ? null
                    : new[] { issuerWithSlash!, issuerNoSlash! },
                ValidateIssuer = opts.Issuer is not null,
                ValidateAudience = false, // we just need sub + aud claims, audience was our client
                ValidateLifetime = false, // logout should work even with expired tokens
                IssuerSigningKeys = signingKeys,
                ValidateIssuerSigningKey = true,
                ClockSkew = TimeSpan.FromMinutes(5)
            };

            var result = await _tokenHandler.ValidateTokenAsync(jwt, validationParams)
                .ConfigureAwait(false);

            if (!result.IsValid)
            {
                _logger?.LogWarning("id_token_hint signature validation failed: {Error}",
                    result.Exception?.Message);
                return (null, null);
            }

            var sub = result.ClaimsIdentity.FindFirst("sub")?.Value;
            var aud = result.ClaimsIdentity.FindFirst("aud")?.Value;
            return (sub, aud);
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to validate id_token_hint");
            return (null, null);
        }
    }
}
