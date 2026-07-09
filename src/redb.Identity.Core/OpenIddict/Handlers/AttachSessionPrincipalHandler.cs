using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using redb.Core;
using redb.Core.Query;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerDescriptor;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Reads <c>session_user_id</c> from the route exchange (set by the HTTP session cookie processor)
/// and builds a <see cref="System.Security.Claims.ClaimsPrincipal"/> for the authorize endpoint.
/// The <c>session_user_id</c> is a <c>_users._id</c>. The handler loads the Core user via
/// <see cref="redb.Core.Providers.IUserProvider"/> and the OIDC profile via <c>RedbObject.Key</c>.
/// </summary>
internal sealed class AttachSessionPrincipalHandler
    : IOpenIddictServerHandler<HandleAuthorizationRequestContext>
{
    private readonly IServiceProvider _sp;
    private readonly ILogger<AttachSessionPrincipalHandler> _logger;

    public AttachSessionPrincipalHandler(IServiceProvider sp, ILogger<AttachSessionPrincipalHandler> logger)
    {
        _sp = sp;
        _logger = logger;
    }

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        CreateBuilder<HandleAuthorizationRequestContext>()
            .UseScopedHandler<AttachSessionPrincipalHandler>()
            // Run BEFORE HandleAuthorizationRequestHandler (which is at AttachPrincipal + 100)
            .SetOrder(OpenIddictServerHandlers.Authentication.AttachPrincipal.Descriptor.Order + 50)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(HandleAuthorizationRequestContext context)
    {
        // If a principal is already set (shouldn't happen, but be safe), skip
        if (context.Principal is not null)
            return;

        var exchange = context.Transaction.GetRouteExchange();
        if (exchange is null)
            return;

        // Check for session_user_id (set by SessionCookieProcessors.ReadSessionCookie)
        if (!exchange.In.Headers.TryGetValue("session_user_id", out var rawUserId) ||
            rawUserId is not long userId)
        {
            // Also try string representation (from header)
            if (rawUserId is string userIdStr && long.TryParse(userIdStr, out userId))
            {
                // parsed OK
            }
            else
            {
                return; // No session — HandleAuthorizationRequestHandler will reject with login_required
            }
        }

        var redb = _sp.GetService<IRedbService>();
        if (redb is null)
            return; // degraded mode — no redb, no session resolution

        // Per-session revocation check: if the cookie carries a session_id, verify the session is still active
        bool sessionMfaVerified = false;
        string? sessionMfaMethod = null;
        long sessionIdForLookup = 0;
        DateTimeOffset? sessionCreatedAt = null;

        if (exchange.In.Headers.TryGetValue("session_id", out var rawSessionId))
        {
            long sessionId = rawSessionId is long sid ? sid :
                rawSessionId is string sidStr && long.TryParse(sidStr, out var parsed) ? parsed : 0;

            if (sessionId > 0)
            {
                sessionIdForLookup = sessionId;
                var sessionService = new SessionService(redb);
                if (await sessionService.IsSessionRevokedAsync(sessionId).ConfigureAwait(false))
                {
                    _logger.LogInformation("Session {SessionId} for user {UserId} is revoked — login_required", sessionId, userId);
                    return; // No principal → OpenIddict rejects with login_required → redirect to login
                }

                // Load MFA flags so the resulting principal carries the correct amr claim
                var sessionObj = await redb.LoadAsync<SessionProps>(sessionId).ConfigureAwait(false);
                if (sessionObj is not null)
                {
                    sessionMfaVerified = sessionObj.Props.MfaVerified;
                    sessionMfaMethod = sessionObj.Props.MfaMethod;
                    // OIDC §2 — auth_time MUST reflect the original authentication, not the
                    // moment the principal is rebuilt from the session cookie. The base
                    // RedbObject.DateCreate is set when LoginService minted the session row,
                    // so it is the right source for the End-User's actual authentication time.
                    sessionCreatedAt = sessionObj.DateCreate;
                }
            }
        }

        var profileService = _sp.GetService<IUserProfileService>();
        if (profileService is not null)
        {
            context.Principal = await profileService.BuildPrincipalAsync(
                userId, context.Request.GetScopes(),
                sessionMfaVerified, sessionMfaMethod).ConfigureAwait(false);
        }
        else
        {
            // Fallback: load manually (degraded mode without DI)
            var coreUser = await redb.UserProvider.GetUserByIdAsync(userId).ConfigureAwait(false);
            if (coreUser is null || !coreUser.Enabled)
                return;
            var oidcObj = await redb.Query<UserProps>()
                .WhereRedb(o => o.Key == coreUser.Id)
                .FirstOrDefaultAsync()
                .ConfigureAwait(false);
            // Lazy-create the GUID identity if missing so legacy users get a stable sub
            // before token issuance.
            if (oidcObj is null)
            {
                oidcObj = new redb.Core.Models.Entities.RedbObject<UserProps>(new UserProps())
                {
                    name = coreUser.Login,
                    key = coreUser.Id,
                    value_guid = Guid.NewGuid()
                };
                await redb.SaveAsync(oidcObj).ConfigureAwait(false);
            }
            else if (oidcObj.value_guid is null || oidcObj.value_guid == Guid.Empty)
            {
                oidcObj.value_guid = Guid.NewGuid();
                await redb.SaveAsync(oidcObj).ConfigureAwait(false);
            }
            context.Principal = IdentityPrincipalBuilder.Build(
                coreUser, oidcObj.value_guid!.Value, oidcObj.Props, context.Request.GetScopes(),
                sessionMfaVerified, sessionMfaMethod);
        }

        _logger.LogDebug(
            "Attached principal from session for user {UserId} (authorize endpoint)", userId);

        // Add sid (session ID) claim per OIDC Front-Channel/Back-Channel Logout specs
        if (context.Principal?.Identity is ClaimsIdentity identity && sessionIdForLookup > 0)
        {
            var sidClaim = new Claim("sid", sessionIdForLookup.ToString());
            sidClaim.SetDestinations(Destinations.AccessToken, Destinations.IdentityToken);
            identity.AddClaim(sidClaim);

            // OIDC §2 — overwrite the auth_time that IdentityPrincipalBuilder stamped at
            // construction (= "now") with the session's actual creation time so max_age
            // and prompt=login-style staleness checks see real elapsed seconds, not zero.
            if (sessionCreatedAt.HasValue)
            {
                var existing = identity.FindAll(Claims.AuthenticationTime).ToList();
                foreach (var c in existing) identity.RemoveClaim(c);
                var authTime = new Claim(
                    Claims.AuthenticationTime,
                    sessionCreatedAt.Value.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture),
                    ClaimValueTypes.Integer64);
                authTime.SetDestinations(Destinations.AccessToken, Destinations.IdentityToken);
                identity.AddClaim(authTime);
            }
        }
    }
}
