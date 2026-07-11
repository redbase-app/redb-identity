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

        // Set once the re-auth gate below is satisfied; the marker cookie is consumed only on the
        // FINAL success (not here) so an intervening consent round-trip does not lose it.
        var reauthGateSatisfied = false;

        // ── Re-authentication gate (OIDC §3.1.2.1) — prompt=login / max_age ──────────────────
        // Both force the End-User to (re)authenticate: prompt=login unconditionally; max_age when
        // the last authentication (auth_time) is older than the allowed age. We enforce them the
        // SAME way — send the user to /login (a plain login_required that the HTTP facade turns
        // into a /login redirect, NOT an error delivered to the RP) and complete once they have
        // re-authenticated. The redirect loop is broken WITHOUT a bypass by a DataProtection-signed
        // re-auth marker cookie (see SessionCookieProcessors.HandleReauthCookie): we stamp "re-auth
        // requested at T" and only accept the request once the session's auth_time is >= T, i.e. the
        // End-User authenticated AFTER we asked. The marker is consumed (cookie expired) on success
        // so a stale marker can never satisfy a later prompt=login. Runs BEFORE the no-principal
        // check so prompt=login for a logged-out user needs only a single /login (the marker is set
        // even without a principal — it is just a timestamp).
        {
            var promptLogin = prompt?.Contains("login") == true;

            // max_age. OpenIddict normalises max_age=0 to null, but §3.1.2.1 still demands re-auth
            // in that case, so read the raw parameter as a fallback.
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

            var maxAgeStale = false;
            if (context.Principal is not null && maxAge.HasValue)
            {
                var authTimeClaim = context.Principal.GetClaim(Claims.AuthenticationTime);
                var nowSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                maxAgeStale = true; // absent auth_time → treat as stale
                if (long.TryParse(authTimeClaim, System.Globalization.NumberStyles.Integer,
                                  System.Globalization.CultureInfo.InvariantCulture, out var authTime))
                {
                    // `>=` so max_age=0 deterministically forces re-auth even at the second boundary.
                    maxAgeStale = (nowSeconds - authTime) >= maxAge.Value;
                }
            }

            if (promptLogin || maxAgeStale)
            {
                var exchange = context.Transaction.GetRouteExchange();

                // The session active on THIS request (0 = none). ReadSessionCookie decodes it from
                // the session ticket into the "session_id" header.
                long currentSessionId = 0;
                if (exchange is not null && exchange.In.Headers.TryGetValue("session_id", out var sidObj))
                {
                    currentSessionId = sidObj is long sl ? sl
                        : (sidObj is string ss && long.TryParse(ss, out var psl) ? psl : 0);
                }

                // Did the End-User sign in again since we forced re-auth? The signed re-auth marker
                // (ReadSessionCookie → "reauth_marked_sid") carries the session that was active when
                // we asked; a fresh /login always mints a NEW session, so a CHANGED active session id
                // proves the re-authentication. Keying on the session id — not the second-precision
                // auth_time — removes the same-second window where an unchanged session could be
                // mistaken for a re-auth.
                var reauthSatisfied = false;
                if (exchange is not null && exchange.In.Headers.TryGetValue("reauth_marked_sid", out var markedObj))
                {
                    long markedSid = markedObj is long ml ? ml
                        : (markedObj is string ms && long.TryParse(ms, out var pml) ? pml : 0);
                    // currentSessionId != 0 covers the logged-out prompt=login case (marked 0, now a
                    // real session); != markedSid covers the logged-in case (session replaced by /login).
                    reauthSatisfied = currentSessionId != 0 && currentSessionId != markedSid;
                }

                if (reauthSatisfied)
                {
                    // Re-auth done — proceed. The marker is consumed on the final success below,
                    // so a consent round-trip in between does not drop it.
                    reauthGateSatisfied = true;
                }
                else
                {
                    // Force (re)authentication: mark the current session and reject with a plain
                    // login_required (no force_login) so the facade redirects to /login.
                    if (exchange is not null) exchange.Properties["reauth_set"] = currentSessionId;
                    context.Reject(
                        error: Errors.LoginRequired,
                        description: promptLogin
                            ? "Re-authentication required (prompt=login)."
                            : "Re-authentication required (max_age exceeded).");
                    return;
                }
            }
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

        // Re-auth (prompt=login / max_age) completed successfully — consume the marker so it can
        // never satisfy a LATER prompt=login (that would be a bypass). Done only here, on the final
        // success after the consent gate, so an intervening /consent round-trip keeps the marker.
        if (reauthGateSatisfied)
        {
            var reauthExchange = context.Transaction.GetRouteExchange();
            if (reauthExchange is not null)
                reauthExchange.Properties["reauth_clear"] = true;
        }

        // Session is now created at login time (LoginProcessor) and tracked via session_id in cookie.
        // Per-app authorization tracking is handled by OpenIddict's built-in authorization store.

        _logger.LogDebug("Authorization granted for user {UserId} via session", userId);
    }
}
