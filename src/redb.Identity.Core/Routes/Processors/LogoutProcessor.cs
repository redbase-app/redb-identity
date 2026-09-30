using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;
using redb.Identity.Core.Module;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.RedbCore.Extensions;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// Logout processor: acts on the browser's own OP session (the user and session ids that
/// <c>ReadSessionCookie</c> decoded from the session cookie), validates an optional <c>id_token_hint</c>
/// (OIDC RP-Initiated Logout 1.0) and revokes sessions via SessionService. Without a session the request
/// completes and ends nothing.
/// </summary>
internal sealed class LogoutProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;
    private readonly ILogger? _logger;
    private readonly IOptionsMonitor<OpenIddictServerOptions> _serverOptions;
    private readonly LogoutConfirmationProtector _confirmation;
    private static readonly JsonWebTokenHandler _tokenHandler = new();

    public LogoutProcessor(
        IRouteContext context,
        IOptionsMonitor<OpenIddictServerOptions> serverOptions,
        LogoutConfirmationProtector confirmation,
        string? redbName = null,
        ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(confirmation);
        _context = context;
        _serverOptions = serverOptions;
        _confirmation = confirmation;
        _redbName = redbName;
        _logger = logger;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var redb = _context.GetRedbService(_redbName, exchange);

        // The subject of a logout is the browser's own OP session: the user and session ids that
        // ReadSessionCookie decoded from the verified session ticket into the exchange headers (the facade
        // strips those header names off the request first, so they are ours). Nothing in the request body
        // chooses the user. This endpoint is reachable only through the public HTTP facade, where a body
        // value is the caller's word; reading "userId" from it let an anonymous POST sign any user out of
        // every session and notify every relying party. Signing another user out is an operator action and
        // goes through ManageSessions ("logout"), behind the management gate.
        var userId = HeaderLong(exchange, "session_user_id");
        var sessionId = HeaderLong(exchange, "session_id");
        var idTokenHint = BodyString(exchange, "id_token_hint");

        if (userId <= 0)
        {
            // No OP session in this browser (no cookie, or a ticket that did not verify). RP-Initiated
            // Logout 1.0 §2 still has the OP complete the request — the RP's post_logout_redirect_uri is
            // handled after this processor — so this is a logout that ended nothing, not an error. A hint,
            // if any, names a user, but the request does not come from that user's browser and acts on nobody.
            _logger?.LogInformation(
                "Logout without an OP session: nothing to end (id_token_hint present: {HasHint})",
                !string.IsNullOrEmpty(idTokenHint));
            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = new Dictionary<string, object?>
            {
                ["success"] = true,
                ["sessions_revoked"] = 0,
                ["backchannel_delivered"] = 0
            };
            return;
        }

        // The user's public subject: the sub of every token issued for them, hence what an id_token_hint
        // carries and what a relying party matches a logout token against. Not the core user id the session
        // ticket carries.
        var subject = await ResolveSubjectAsync(redb, userId).ConfigureAwait(false);

        // OIDC RP-Initiated Logout: process id_token_hint if present. A hint that verifies and names the
        // session's user is the relying party's proof of intent — the request came from an RP that holds
        // this user's id_token, not from a page the user happened to visit.
        var intentProven = false;
        if (!string.IsNullOrEmpty(idTokenHint))
        {
            var (hintSub, hintAud) = await ValidateIdTokenHintAsync(idTokenHint);

            if (hintSub is null)
            {
                // Signature invalid or missing sub — treat as no hint (already logged inside)
            }
            else if (subject == Guid.Empty || !Guid.TryParse(hintSub, out var hintSubject) || hintSubject != subject)
            {
                // OIDC RP-Initiated Logout §2: sub mismatch → MUST treat as if hint not provided
                _logger?.LogWarning(
                    "id_token_hint sub '{HintSub}' does not match session user {UserId} — ignoring hint",
                    hintSub, userId);
            }
            else
            {
                intentProven = true;
                // Valid hint, sub matches — safe to use aud for post_logout_redirect_uri scoping
                if (hintAud is not null)
                    exchange.Properties["logout_client_id"] = hintAud;
            }
        }

        // Without that proof, the request has to carry the confirmation state from the page this server
        // showed for this very session (LogoutConfirmationProtector). The session cookie alone proves
        // nothing about intent: a cross-site top-level navigation carries it too, and a link on any page
        // could otherwise end the visitor's OP session. The facade renders the page from this answer;
        // the request's own RP parameters travel with it so the redirect back still happens.
        if (!intentProven && !_confirmation.Accepts(BodyString(exchange, "logout_state"), userId, sessionId))
        {
            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = new Dictionary<string, object?>
            {
                ["confirm_required"] = true,
                ["logout_state"] = _confirmation.Issue(userId, sessionId),
                ["post_logout_redirect_uri"] = BodyString(exchange, "post_logout_redirect_uri"),
                ["state"] = BodyString(exchange, "state"),
                ["client_id"] = BodyString(exchange, "client_id"),
            };
            exchange.Properties["logout_confirm_required"] = true;
            return;
        }

        var session = new SessionService(redb);
        int sessionsRevoked;

        // Whom to tell, collected BEFORE anything is revoked (revocation flips the rows this reads).
        var targets = await CollectBackchannelTargetsAsync(redb, userId, sessionId, subject, ct).ConfigureAwait(false);

        if (sessionId > 0)
        {
            // Per-session logout ends this OP session and tells the relying parties that signed in through
            // it (back-channel below). It deliberately leaves the user's grants alone: refresh tokens exist
            // only with offline_access, which OIDC Core §11 defines as access while the End-User is not
            // logged in, so signing out of one browser must not sign the user's other applications out.
            // Keycloak keeps offline tokens across a session logout and Duende revokes nothing on logout for
            // the same reason. Ending every grant is the full logout (password change or reset, operator,
            // SCIM deactivation): SessionService.LogoutAsync.
            sessionsRevoked = await session.RevokeAsync(sessionId, ct);
        }
        else
        {
            // A ticket without a session id (legacy): end every session of the user.
            sessionsRevoked = await session.LogoutAsync(userId, ct);
        }

        // Best-effort backchannel logout fan-out. Failures are logged but never break logout.
        // BackchannelLogoutDispatcher is registered in the Identity child container — resolve
        // through the IRouteContext scope helper, NOT exchange.ServiceProvider (that's the
        // *host* container, where the dispatcher is not registered).
        var dispatcher = _context.GetIdentityServiceOrDefault<BackchannelLogoutDispatcher>(exchange);
        int backchannelDelivered = 0;
        if (dispatcher is not null && subject != Guid.Empty)
        {
            foreach (var (sid, applications) in targets)
            {
                try
                {
                    backchannelDelivered += await dispatcher.DispatchAsync(
                        redb, subject, sid, applications, ct).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "BackchannelLogoutDispatcher.DispatchAsync threw for session {SessionId} — logout flow continues.", sid);
                }
            }
        }

        var backchannelTargets = targets.SelectMany(t => t.Applications).Distinct().Count();
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
            BackchannelTargets = backchannelTargets
        };
    }

    /// <summary>
    /// Whom the back-channel logout goes to, grouped by the session whose id the logout token carries as
    /// <c>sid</c> (Back-Channel Logout 1.0 §2.1: the OP notifies the relying parties the End-User logged in
    /// to through the session being ended). For the session being ended: the relying parties that obtained
    /// tokens through it (<see cref="SessionProps.ClientApplicationIds"/>, bound at the authorization
    /// endpoint) and the application the session was opened for, if any. For a logout of every session (a
    /// ticket without a session id): each active session's relying parties with that session's id, and,
    /// with no <c>sid</c>, the relying parties that hold live authorizations or tokens for the user outside
    /// any browser session (ROPC, device flow) — they have no session to match, so <c>sub</c> is all the
    /// token can say.
    /// </summary>
    private static async Task<List<(long SessionId, IReadOnlyCollection<long> Applications)>> CollectBackchannelTargetsAsync(
        IRedbService redb, long userId, long sessionId, Guid subject, CancellationToken ct)
    {
        var targets = new List<(long SessionId, IReadOnlyCollection<long> Applications)>();

        if (sessionId > 0)
        {
            var current = await redb.LoadAsync<SessionProps>(sessionId).ConfigureAwait(false);
            if (current is not null && current.Props.Status != "revoked")
            {
                var applications = ApplicationsOf(current);
                if (applications.Count > 0)
                    targets.Add((sessionId, applications));
            }
            return targets;
        }

        // Sessions use Key == userId (long).
        var sessions = await redb.Query<SessionProps>()
            .WhereRedb(o => o.Key == userId)
            .Where(p => p.Status == "active")
            .ToListAsync()
            .ConfigureAwait(false);
        var covered = new HashSet<long>();
        foreach (var s in sessions)
        {
            var applications = ApplicationsOf(s);
            if (applications.Count == 0) continue;
            targets.Add((s.id, applications));
            covered.UnionWith(applications);
        }

        if (subject == Guid.Empty)
            return targets;

        // Authorizations and tokens are written by OpenIddict stores via SetSubjectAsync, which keys
        // them by the public subject (_objects.value_guid), not by Key.
        var sessionless = new HashSet<long>();
        var auths = await redb.Query<AuthorizationProps>()
            .WhereRedb(o => o.ValueGuid == subject)
            .Where(p => p.Status != "revoked")
            .ToListAsync()
            .ConfigureAwait(false);
        foreach (var a in auths)
            if (a.Props.ApplicationObjectId > 0 && !covered.Contains(a.Props.ApplicationObjectId))
                sessionless.Add(a.Props.ApplicationObjectId);

        // ROPC and other non-interactive grants emit access/refresh tokens without creating an
        // authorization row; tokens always carry ApplicationObjectId.
        var tokens = await redb.Query<TokenProps>()
            .WhereRedb(o => o.ValueGuid == subject)
            .Where(p => p.Status != "revoked")
            .ToListAsync()
            .ConfigureAwait(false);
        foreach (var t in tokens)
            if (t.Props.ApplicationObjectId > 0 && !covered.Contains(t.Props.ApplicationObjectId))
                sessionless.Add(t.Props.ApplicationObjectId);

        if (sessionless.Count > 0)
            targets.Add((0, sessionless));
        return targets;
    }

    private static IReadOnlyCollection<long> ApplicationsOf(RedbObject<SessionProps> session)
    {
        var applications = new HashSet<long>(session.Props.ClientApplicationIds ?? []);
        if (session.Props.ApplicationObjectId > 0)
            applications.Add(session.Props.ApplicationObjectId);
        return applications;
    }

    private static long HeaderLong(IExchange exchange, string name)
    {
        if (!exchange.In.Headers.TryGetValue(name, out var raw)) return 0;
        return raw switch
        {
            long value => value,
            string text when long.TryParse(text, out var parsed) => parsed,
            _ => 0,
        };
    }

    private static string? BodyString(IExchange exchange, string name) => exchange.In.Body switch
    {
        Dictionary<string, object?> dict when dict.TryGetValue(name, out var value) => value?.ToString(),
        Dictionary<string, string> sdict when sdict.TryGetValue(name, out var value) => value,
        _ => null,
    };

    /// <summary>
    /// The user's public subject GUID — the <c>sub</c> of every token and the <c>value_guid</c> OpenIddict's
    /// stores key authorizations and tokens by. It lives on the UserProps "oidc" sibling object
    /// (<c>Key == coreUser.Id</c>), not on the core-user object itself. <see cref="Guid.Empty"/> when the
    /// user has no such object.
    /// </summary>
    private static async Task<Guid> ResolveSubjectAsync(IRedbService redb, long userId)
    {
        var userProps = await redb.Query<UserProps>()
            .WhereRedb(o => o.Key == userId)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);
        return userProps?.value_guid ?? Guid.Empty;
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
