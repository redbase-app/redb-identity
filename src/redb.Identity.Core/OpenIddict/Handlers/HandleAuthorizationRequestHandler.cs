using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using redb.Core;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerDescriptor;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Handles <see cref="HandleAuthorizationRequestContext"/> for the authorization_code flow.
/// Expects the principal to be already attached by <see cref="AttachSessionPrincipalHandler"/>
/// (session cookie → user ID → principal). If no principal is present, rejects with <c>login_required</c>.
/// Also handles consent tracking and session record creation.
/// </summary>
internal sealed class HandleAuthorizationRequestHandler : IOpenIddictServerHandler<HandleAuthorizationRequestContext>
{
    private readonly IServiceProvider _sp;
    private readonly ILogger<HandleAuthorizationRequestHandler> _logger;

    public HandleAuthorizationRequestHandler(IServiceProvider sp, ILogger<HandleAuthorizationRequestHandler> logger)
    {
        _sp = sp;
        _logger = logger;
    }

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        CreateBuilder<HandleAuthorizationRequestContext>()
            .UseScopedHandler<HandleAuthorizationRequestHandler>()
            .SetOrder(OpenIddictServerHandlers.Authentication.AttachPrincipal.Descriptor.Order + 100)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(HandleAuthorizationRequestContext context)
    {
        // RFC 9126 §5 — per-client Pushed Authorization Request enforcement. When the client's
        // registration carries `require_pushed_authorization_requests=true`, any direct
        // /connect/authorize that did NOT come through /connect/par (request_uri parameter)
        // must be rejected with `invalid_request` BEFORE we surface other errors like
        // login_required / consent_required — the request shape itself is non-conformant
        // for this client. Layered on top of the global enforcement flag so individual
        // high-assurance clients (FAPI / financial-grade APIs) can demand PAR even when
        // the rest of the deployment doesn't.
        var clientIdEarly = context.Request.ClientId;
        if (!string.IsNullOrEmpty(clientIdEarly) && string.IsNullOrEmpty(context.Request.RequestUri))
        {
            var redbEarly = _sp.GetService<IRedbService>();
            if (redbEarly is not null)
            {
                var consentSvcEarly = new ConsentService(redbEarly);
                var appIdEarly = await consentSvcEarly.FindApplicationIdAsync(clientIdEarly).ConfigureAwait(false);
                if (appIdEarly is > 0)
                {
                    var appEarly = (await redbEarly.LoadAsync<ApplicationProps>(appIdEarly.Value)
                        .ConfigureAwait(false))?.Hydrate();
                    if (appEarly?.Props.RequirePushedAuthorizationRequests == true)
                    {
                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "Pushed Authorization Requests (RFC 9126) are required for this " +
                                         "client. Submit the authorization request to /connect/par first " +
                                         "and use the returned request_uri.");
                        return;
                    }
                }
            }
        }

        var prompt = context.Request.Prompt;

        // prompt=login: force re-authentication even if session exists
        if (prompt?.Contains("login") == true)
        {
            var exchange = context.Transaction.GetRouteExchange();
            if (exchange is not null)
                exchange.Properties["force_login"] = true;

            context.Reject(
                error: Errors.LoginRequired,
                description: "Re-authentication required (prompt=login).");
            return;
        }

        // prompt=none: MUST NOT display any UI — if no principal, reject immediately.
        // Flag the exchange so downstream HTTP processors skip their /login & /consent UI
        // overrides; the OIDC §3.1.2.6 contract requires the error to flow back to redirect_uri.
        if (prompt?.Contains("none") == true && context.Principal is null)
        {
            var exchange = context.Transaction.GetRouteExchange();
            if (exchange is not null)
                exchange.Properties["prompt_none"] = true;

            context.Reject(
                error: Errors.LoginRequired,
                description: "No active session and prompt=none was requested.");
            return;
        }

        // No principal = no session = user not authenticated → login_required
        if (context.Principal is null)
        {
            context.Reject(
                error: Errors.LoginRequired,
                description: "User authentication is required. Please log in.");
            return;
        }

        // OIDC Core §3.1.2.1 — max_age: if supplied, the OP MUST re-authenticate the
        // End-User when more than `max_age` seconds have elapsed since their last active
        // authentication. We read from `context.Request.MaxAge` and fall back to the
        // raw parameter dictionary because OpenIddict's typed property normalises
        // `max_age=0` to null (treats it as "no constraint") even though OIDC §3.1.2.1
        // explicitly demands re-auth in that case. We compare against the `auth_time`
        // claim (NumericDate) emitted by IdentityPrincipalBuilder; an absent auth_time
        // means the session predates the claim and is treated as stale.
        long? maxAge = context.Request.MaxAge;
        if (!maxAge.HasValue)
        {
            var rawParam = context.Request.GetParameter("max_age");
            var raw = rawParam.HasValue ? rawParam.Value.Value?.ToString() : null;
            if (long.TryParse(raw, System.Globalization.NumberStyles.Integer,
                              System.Globalization.CultureInfo.InvariantCulture, out var rawMaxAge)
                && rawMaxAge >= 0)
            {
                maxAge = rawMaxAge;
            }
        }
        if (maxAge.HasValue)
        {
            var authTimeClaim = context.Principal.GetClaim(Claims.AuthenticationTime);
            var nowSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var stale = true;
            if (long.TryParse(authTimeClaim, System.Globalization.NumberStyles.Integer,
                              System.Globalization.CultureInfo.InvariantCulture, out var authTime))
            {
                // Use `>=` so that `max_age=0` deterministically forces re-auth even when
                // the clock has not advanced past the second boundary since /login.
                // OIDC §3.1.2.1 says "MORE than max_age seconds have elapsed" — for the
                // degenerate max_age=0 case implementations universally treat any elapsed
                // time (including the boundary) as triggering re-auth, otherwise the
                // parameter is unusable.
                stale = (nowSeconds - authTime) >= maxAge.Value;
            }
            if (stale)
            {
                var exchange = context.Transaction.GetRouteExchange();
                if (exchange is not null) exchange.Properties["force_login"] = true;
                context.Reject(
                    error: Errors.LoginRequired,
                    description: $"Re-authentication required (max_age={maxAge.Value} exceeded).");
                return;
            }
        }

        // The public sub claim is now a GUID; the bigint _users._id rides alongside in
        // the internal `redb:user_id` claim emitted by IdentityPrincipalBuilder.
        var subject = context.Principal.GetClaim(Claims.Subject);
        var internalUid = context.Principal.GetClaim(IdentityPrincipalBuilder.InternalUserIdClaim);
        if (string.IsNullOrEmpty(subject) || string.IsNullOrEmpty(internalUid) || !long.TryParse(internalUid, out var userId))
        {
            context.Reject(
                error: Errors.ServerError,
                description: "Invalid session principal: missing subject.");
            return;
        }

        // ── Consent tracking ──
        var scopes = context.Request.GetScopes();
        var clientId = context.Request.ClientId;
        long appObjectId = 0;

        // ── Consent + session tracking (requires IRedbService) ──
        var redb = _sp.GetService<IRedbService>();
        if (redb is null)
        {
            // Degraded mode — no tracking, just log and return
            _logger.LogDebug("Authorization granted for user {UserId} (degraded mode)", userId);
            return;
        }

        if (!string.IsNullOrEmpty(clientId))
        {
            var consentService = new ConsentService(redb);
            var appId = await consentService.FindApplicationIdAsync(clientId)
                .ConfigureAwait(false);

            if (appId is > 0)
            {
                appObjectId = appId.Value;
                var app = (await redb.LoadAsync<ApplicationProps>(appId.Value)
                    .ConfigureAwait(false))?.Hydrate();

                if (app?.Props.ConsentType == ConsentTypes.Explicit)
                {
                    var scopeList = scopes.ToList();
                    var forceConsent = prompt?.Contains("consent") == true;
                    var existingConsent = forceConsent
                        ? null // prompt=consent: always re-prompt regardless of prior consent
                        : await consentService.CheckAsync(
                            userId, appId.Value, scopeList).ConfigureAwait(false);

                    if (existingConsent is null)
                    {
                        // Signal to the HTTP facade that consent is required.
                        // The facade will redirect to a consent page instead of completing authorize.
                        // After the user grants consent, they'll be redirected back to /connect/authorize.
                        var exchange = context.Transaction.GetRouteExchange();
                        if (exchange is not null)
                        {
                            exchange.Properties["consent_required"] = true;
                            exchange.Properties["consent_client_id"] = clientId!;
                            exchange.Properties["consent_app_name"] = app.Name ?? clientId!;
                            exchange.Properties["consent_scopes"] = string.Join(" ", scopeList);
                            exchange.Properties["consent_user_id"] = userId;
                        }

                        // Reject with consent_required — the response post-processor
                        // (or HTTP facade) will intercept this and redirect to the consent page
                        // instead of sending the error to the client's redirect_uri.
                        context.Reject(
                            error: "consent_required",
                            description: "User consent is required for the requested scopes.");

                        _logger.LogDebug(
                            "Consent required for user {UserId} to client '{ClientId}' — scopes: [{Scopes}]",
                            userId, clientId, string.Join(", ", scopeList));
                        return;
                    }
                }
            }
        }

        // Session is now created at login time (LoginProcessor) and tracked via session_id in cookie.
        // Per-app authorization tracking is handled by OpenIddict's built-in authorization store.

        _logger.LogDebug("Authorization granted for user {UserId} via session", userId);
    }
}
