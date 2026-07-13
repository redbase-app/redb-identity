using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using redb.Identity.Contracts.Routes;
using redb.Identity.Contracts.Cors;
using redb.Identity.Http.Controllers;
using redb.Identity.Http.Endpoints;
using redb.Identity.Http.Security;
using redb.Identity.Http.Cors;
using redb.Identity.Http.Processors;
using redb.Route.Abstractions;
using redb.Route.Controllers;
using redb.Route.Controllers.Extensions;
using redb.Route.Core;
using redb.Route.Http;
using redb.Identity.Contracts.Configuration;
using redb.Identity.Contracts.Federation;
using redb.Identity.Contracts.Serialization;

namespace redb.Identity.Http;

/// <summary>
/// HTTP facade for redb.Identity. Maps standard OIDC HTTP paths to
/// <c>direct-vm://identity-*</c> internal routes and exposes a REST management API
/// via <see cref="RedbController"/>-based controllers.
/// <para>
/// Protocol endpoints (<c>/connect/*</c>, <c>/.well-known/*</c>) use hand-crafted
/// processors for precise HTTP ↔ OIDC translation. Management endpoints
/// (<c>/api/v1/identity/*</c>) use <see cref="ControllerRegistry"/> dispatch.
/// </para>
/// </summary>
public class HttpFacadeRouteBuilder : RouteBuilder
{
    /// <summary>
    /// RFC 7591 Dynamic Client Registration endpoint path. Hard-coded here because
    /// it is referenced both by the route registration and by the discovery document
    /// patcher; if it ever moves under <c>/api/v1/identity/...</c>, both call sites
    /// must change together.
    /// </summary>
    private const string DynamicRegistrationPath = "/connect/register";

    private readonly IdentityTransportOptions _transportOptions;
    private readonly SessionTicketService _ticketService;
    private readonly BrokeredPostLogoutRedirectValidator? _postLogoutValidator;
    private readonly Contracts.Mfa.IMfaStateInspector? _mfaStateInspector;
    private readonly IRegisteredClientOriginRegistry? _originRegistry;

    // URI scheme and shared TLS query parameters applied to EVERY endpoint below. When
    // IdentityTransport:Http:Ssl is true these become "https" + "&ssl=true&sslCertPath=…", so all
    // endpoints on the same host:port agree on TLS (SharedHttpServerManager rejects a mixed
    // http/https server). Computed once at the top of Configure().
    private string _scheme = "http";
    private string _sslParams = "";

    public HttpFacadeRouteBuilder(
        SessionTicketService ticketService,
        IOptions<IdentityTransportOptions>? transportOptions = null,
        BrokeredPostLogoutRedirectValidator? postLogoutValidator = null,
        Contracts.Mfa.IMfaStateInspector? mfaStateInspector = null,
        IRegisteredClientOriginRegistry? originRegistry = null)
    {
        _ticketService = ticketService;
        _transportOptions = transportOptions?.Value ?? new IdentityTransportOptions();
        _postLogoutValidator = postLogoutValidator;
        _mfaStateInspector = mfaStateInspector;
        _originRegistry = originRegistry;
    }

    protected override void Configure()
    {
        var port = _transportOptions.Http.PublicPort;
        var mgmtPort = _transportOptions.Http.ManagementPort ?? port;

        // TLS: compute scheme + ssl query params once, apply uniformly to every From(...) below.
        if (_transportOptions.Http.Ssl)
        {
            var certPath = _transportOptions.Http.SslCertPath
                ?? throw new InvalidOperationException(
                    "IdentityTransport:Http:SslCertPath is required when IdentityTransport:Http:Ssl=true.");
            _scheme = "https";
            _sslParams = $"&ssl=true&sslCertPath={Uri.EscapeDataString(certPath)}";
            if (!string.IsNullOrEmpty(_transportOptions.Http.SslCertPassword))
                _sslParams += $"&sslCertPassword={Uri.EscapeDataString(_transportOptions.Http.SslCertPassword)}";
        }

        // C15 / per-route CORS: wire up the registered-client origin resolver before any
        // route is registered so that the shared HttpComponent picks it up via its
        // DefaultCors mechanism. The resolver is only consumed for endpoints whose URI
        // declares cors=true *without* an explicit corsOrigins (see HttpComponent.ApplyCorsDefaults).
        // For public endpoints (well-known) we inline corsOrigins=*; for management/redirect
        // endpoints we omit cors entirely.
        ConfigureCorsResolver();

        ConfigureProtocolEndpoints(port);
        ConfigureDiscoveryEndpoints(port);

        // Public read-only projection of the federation provider list. Registered BEFORE
        // ConfigureManagementApi because that one installs a catch-all
        // /api/v1/identity/{**path} route that would otherwise capture
        // /api/v1/identity/federation-providers/public and dispatch it to
        // FederationProvidersController.Get({id="public"}) → "Id is required" error.
        // Exposed even when no providers are configured (empty array) so callers can rely
        // on a stable contract. Skipped only when federation is disabled at the feature
        // flag level. Registered on both the public and management ports (when they differ)
        // so browser-facing login pages on the public origin and server-to-server callers
        // on the management origin can both reach it.
        if (_transportOptions.Features.EnableFederation)
        {
            ConfigurePublicFederationProvidersEndpoint(port, routeIdSuffix: "public");
            if (mgmtPort != port)
                ConfigurePublicFederationProvidersEndpoint(mgmtPort, routeIdSuffix: "mgmt");
        }

        ConfigureManagementApi(mgmtPort);
        ConfigureBootstrapEndpoint(mgmtPort);

        if (_transportOptions.Features.EnableScim)
            ConfigureScimApi(mgmtPort);

        if (_transportOptions.Features.EnableFederation && _transportOptions.FederationProviders.Count > 0)
            ConfigureFederationEndpoints(port);
    }

    /// <summary>
    /// Installs the CORS origin resolver on the shared <see cref="HttpComponent"/>'s
    /// <c>DefaultCors</c>. Resolver precedence (first non-null wins):
    /// <list type="number">
    ///   <item>caller-supplied <see cref="HttpTransportOptions.CorsOriginsResolver"/>;</item>
    ///   <item>registered-client resolver (when
    ///   <see cref="HttpTransportOptions.CorsRegisteredClientOriginsEnabled"/> is true);</item>
    ///   <item>no resolver \u2014 only static <see cref="HttpTransportOptions.AdditionalAllowedOrigins"/>
    ///   (passed verbatim to the registry as additional origins).</item>
    /// </list>
    /// No-op when CORS is disabled at the transport level.
    /// </summary>
    private void ConfigureCorsResolver()
    {
        if (!_transportOptions.Http.CorsEnabled) return;

        // The HttpComponent owns the per-server registry (DefaultCors is its property),
        // so we look it up via the route context's component registry rather than DI \u2014
        // it is added by the host with `ctx.AddComponent(new HttpComponent { ... })` and
        // therefore is not necessarily registered in the IServiceProvider.
        var component = Context?.GetComponent<HttpComponent>("http");
        if (component is null) return;

        // Caller-supplied resolver wins outright (it may legitimately want to ignore the
        // registered-client whitelist).
        if (_transportOptions.Http.CorsOriginsResolver is { } customResolver)
        {
            component.DefaultCors.OriginsResolver = customResolver;
            return;
        }

        if (!_transportOptions.Http.CorsRegisteredClientOriginsEnabled)
        {
            // Even when the registered-client whitelist is disabled, AdditionalAllowedOrigins
            // must still flow through a resolver: the route URI declares cors=true without a
            // static corsOrigins, so the dispatcher needs *some* policy or the request gets
            // no headers at all. Build a resolver that consults additional-origins only.
            var additional = _transportOptions.Http.GetEffectiveAdditionalOrigins();
            if (string.IsNullOrEmpty(additional)) return;

            var allowed = additional
                .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                .Select(o => o.ToLowerInvariant())
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            component.DefaultCors.OriginsResolver = req =>
            {
                var origin = req.Headers["Origin"].ToString();
                return !string.IsNullOrEmpty(origin) && allowed.Contains(origin) ? origin : null;
            };
            return;
        }

        var sp = Context?.GetServiceProvider();
        // Phase 9e: prefer the registry passed to the ctor (HTTP-facade child container in
        // .tpkg mode wires BrokeredRegisteredClientOriginRegistry); fall back to the route
        // context SP for embedded test-fixture mode where the host registers Core's impl.
        var registry = _originRegistry ?? sp?.GetService<IRegisteredClientOriginRegistry>();

        // Fallback when the host did not call AddRedbIdentityServer (e.g. a custom test bench):
        // build a transient registry that only honours AdditionalAllowedOrigins.
        var effectiveAdditional = _transportOptions.Http.GetEffectiveAdditionalOrigins();
        if (registry is null)
        {
            // Without an IOpenIddictApplicationManager we cannot derive origins from clients;
            // fall back to additional-origins-only.
            if (string.IsNullOrEmpty(effectiveAdditional)) return;
            var allowed = effectiveAdditional
                .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                .Select(o => o.ToLowerInvariant())
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            component.DefaultCors.OriginsResolver = req =>
            {
                var origin = req.Headers["Origin"].ToString();
                return !string.IsNullOrEmpty(origin) && allowed.Contains(origin) ? origin : null;
            };
            return;
        }

        // Compose: the DI-registered registry knows about OAuth clients; we wrap it so the
        // additional-origins CSV from transport options is also honoured. The wrapper lives
        // in this assembly so the facade does not have to instantiate any Core implementation
        // type directly.
        var composedRegistry = new AdditionalOriginsRegistry(
            registry,
            () => effectiveAdditional);

        var resolver = new RegisteredClientOriginResolver(composedRegistry);
        component.DefaultCors.OriginsResolver = resolver.Resolve;
    }

    /// <summary>
    /// Builds CORS query params for browser-facing OIDC endpoints (token, userinfo, etc.).
    /// Emits <c>cors=true</c> WITHOUT a static origin whitelist so that the component-level
    /// resolver (configured by <see cref="ConfigureCorsResolver"/>) is auto-injected by
    /// <see cref="HttpComponent.ApplyCorsDefaults"/>. When CORS is disabled at the transport
    /// level, returns an empty string.
    /// </summary>
    private string ClientCorsParams()
    {
        if (!_transportOptions.Http.CorsEnabled) return "";

        // Credentials are required so that browsers attach the OIDC session cookie to
        // userinfo / revocation calls. Browsers refuse "*"+credentials, but our resolver
        // never returns "*", so the runtime guard does not trip.
        return "&cors=true&corsCredentials=true";
    }

    /// <summary>
    /// Builds CORS query params for unauthenticated public endpoints (<c>/.well-known/*</c>).
    /// These are safe to expose to any origin: discovery and JWKS are world-readable by
    /// design (RFC 8414 \u00a73, RFC 7517) and contain no per-user data.
    /// Emits a wildcard whitelist; the resolver is suppressed because <c>corsOrigins</c> is
    /// declared explicitly (see <see cref="HttpComponent.ApplyCorsDefaults"/>).
    /// </summary>
    private string PublicCorsParams()
    {
        if (!_transportOptions.Http.CorsEnabled) return "";
        return "&cors=true&corsOrigins=*";
    }

    /// <summary>
    /// OIDC protocol endpoints: token, authorize, userinfo, introspect, revoke.
    /// Each HTTP route maps to a corresponding <c>direct-vm://identity-*</c> route.
    /// </summary>
    private void ConfigureProtocolEndpoints(int port)
    {
        var cookieMaxAge = _transportOptions.SessionCookieLifetime;
        var loginPath = _transportOptions.Paths.Login;
        var consentPath = _transportOptions.Paths.Consent;
        var secureCookie = _transportOptions.Issuer.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase);
        var cookieOpts = _transportOptions.Cookies;
        var sessionCookieName = cookieOpts.SessionCookieName;
        var sessionSameSite = cookieOpts.SessionSameSite;
        var useHostPrefix = cookieOpts.UseHostPrefix;

        // Token endpoint — POST only, form-encoded client auth
        From($"{_scheme}:POST:0.0.0.0:{port}/connect/token?inOut=true{_sslParams}{ClientCorsParams()}")
            .RouteId("http-token")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process(HttpIdentityProcessors.MapHttpToIdentityHeaders)
            .Process(HttpIdentityProcessors.MapFormToBody)
            .To(IdentityEndpoints.Token)
            .Process(HttpIdentityProcessors.MapOAuthErrorToHttpStatus)
            .Process(HttpIdentityProcessors.SerializeJsonResponse)
            .Process(HttpIdentityProcessors.AddNoStoreCacheHeaders); // RFC 6749 §5.1

        // Pushed Authorization Request endpoint (RFC 9126 / Z6) — POST only,
        // form-encoded client auth. Mirrors the Token endpoint pipeline.
        if (_transportOptions.Features.EnablePushedAuthorization)
        {
            From($"{_scheme}:POST:0.0.0.0:{port}/connect/par?inOut=true{_sslParams}{ClientCorsParams()}")
                .RouteId("http-par")
                .Process(HttpIdentityProcessors.PropagateCorrelationId)
                .Process(HttpIdentityProcessors.MapHttpToIdentityHeaders)
                .Process(HttpIdentityProcessors.MapFormToBody)
                .To(IdentityEndpoints.PushedAuthorization)
                .Process(HttpIdentityProcessors.MapOAuthErrorToHttpStatus)
                .Process(HttpIdentityProcessors.SerializeJsonResponse)
                .Process(HttpIdentityProcessors.AddNoStoreCacheHeaders); // RFC 6749 §5.1
        }

        // Authorization endpoint — GET (query params) + POST (form body)
        // Session cookie is read before routing so AttachSessionPrincipalHandler can use it
        From($"{_scheme}:GET:0.0.0.0:{port}/connect/authorize?inOut=true{_sslParams}")
            .RouteId("http-authorize-get")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process((e, ct) => SessionCookieProcessors.ReadSessionCookie(e, ct, _ticketService, cookieMaxAge, sessionCookieName))
            .Process(HttpIdentityProcessors.MapQueryToBody)
            .To(IdentityEndpoints.Authorize)
            .Process(HttpIdentityProcessors.HandleRedirectResponse)
            .Process((e, ct) => SessionCookieProcessors.RedirectToLogin(e, ct, loginPath))
            .Process((e, ct) => SessionCookieProcessors.RedirectToConsent(e, ct, consentPath))
            .Process((e, ct) => SessionCookieProcessors.HandleReauthCookie(e, ct, _ticketService, secureCookie, sessionSameSite, useHostPrefix))
            .Process(HttpIdentityProcessors.MapOAuthErrorToHttpStatus)
            .Process((e, ct) => HttpIdentityProcessors.RenderAuthorizeErrorPage(e, ct, _transportOptions))
            .Process(HttpIdentityProcessors.SerializeJsonResponse);

        From($"{_scheme}:POST:0.0.0.0:{port}/connect/authorize?inOut=true{_sslParams}")
            .RouteId("http-authorize-post")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process((e, ct) => SessionCookieProcessors.ReadSessionCookie(e, ct, _ticketService, cookieMaxAge, sessionCookieName))
            .Process(HttpIdentityProcessors.MapHttpToIdentityHeaders)
            .Process(HttpIdentityProcessors.MapFormToBody)
            .To(IdentityEndpoints.Authorize)
            .Process(HttpIdentityProcessors.HandleRedirectResponse)
            .Process((e, ct) => SessionCookieProcessors.RedirectToLogin(e, ct, loginPath))
            .Process((e, ct) => SessionCookieProcessors.RedirectToConsent(e, ct, consentPath))
            .Process((e, ct) => SessionCookieProcessors.HandleReauthCookie(e, ct, _ticketService, secureCookie, sessionSameSite, useHostPrefix))
            .Process(HttpIdentityProcessors.MapOAuthErrorToHttpStatus)
            .Process((e, ct) => HttpIdentityProcessors.RenderAuthorizeErrorPage(e, ct, _transportOptions))
            .Process(HttpIdentityProcessors.SerializeJsonResponse);

        // Login page — GET renders form, POST submits credentials → session cookie
        From($"{_scheme}:GET:0.0.0.0:{port}{loginPath}?inOut=true{_sslParams}")
            .RouteId("http-login-get")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process((e, ct) => LoginPageProcessors.RenderLoginPage(e, ct, loginPath, _transportOptions))
            .Process(HttpIdentityProcessors.SerializeJsonResponse);

        From($"{_scheme}:POST:0.0.0.0:{port}{loginPath}?inOut=true{_sslParams}")
            .RouteId("http-login-post")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process(HttpIdentityProcessors.MapFormToBody)
            .To(IdentityEndpoints.Login)
            .Process((e, ct) => SessionCookieProcessors.WriteSessionCookie(e, ct, _ticketService, cookieMaxAge, secureCookie, sessionCookieName, sessionSameSite, useHostPrefix))
            // B3 §4: materialize body["mfa_state"] as __Host-redb.identity.mfa cookie.
            // Runs BEFORE HandleLoginResponse so the cookie is placed on the body-carrying
            // message before the response gets replaced with a 302 (HandleLoginResponse
            // preserves Set-Cookie via ExtractSetCookie).
            .Process((e, ct) => MfaCookieProcessors.WriteMfaStateCookie(e, ct, secureCookie, CookieSameSiteMode.Strict, useHostPrefix, TimeSpan.FromMinutes(5)))
            .Process((e, ct) => LoginPageProcessors.HandleLoginResponse(e, ct, loginPath, _transportOptions))
            .Process(HttpIdentityProcessors.SerializeJsonResponse);

        // MFA TOTP verification page — GET renders form, POST verifies code → session cookie
        var mfaPath = _transportOptions.Paths.Mfa;
        var mfaRecoveryPath = _transportOptions.Paths.MfaRecovery;

        From($"{_scheme}:GET:0.0.0.0:{port}{mfaPath}?inOut=true{_sslParams}")
            .RouteId("http-mfa-get")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            // B3 §4: pull mfa_state out of the __Host-redb.identity.mfa cookie so the page
            // can render without any URL query parameter.
            .Process(MfaCookieProcessors.ReadMfaStateCookie)
            .Process((e, ct) => MfaPageProcessors.RenderMfaPage(e, ct, mfaPath, _transportOptions, _mfaStateInspector))
            .Process(HttpIdentityProcessors.SerializeJsonResponse);

        From($"{_scheme}:POST:0.0.0.0:{port}{mfaPath}?inOut=true{_sslParams}")
            .RouteId("http-mfa-post")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process(HttpIdentityProcessors.MapFormToBody)
            .Process(MfaCookieProcessors.ReadMfaStateCookie)
            .To(IdentityEndpoints.MfaVerify)
            .Process((e, ct) => SessionCookieProcessors.WriteSessionCookie(e, ct, _ticketService, cookieMaxAge, secureCookie, sessionCookieName, sessionSameSite, useHostPrefix))
            .Process((e, ct) => MfaCookieProcessors.ClearMfaStateCookieOnSuccess(e, ct, secureCookie, CookieSameSiteMode.Strict, useHostPrefix))
            .Process((e, ct) => MfaPageProcessors.HandleMfaVerifyResponse(e, ct, mfaPath, _transportOptions))
            .Process(HttpIdentityProcessors.SerializeJsonResponse);

        // MFA recovery code page — GET renders form, POST verifies recovery code → session cookie
        From($"{_scheme}:GET:0.0.0.0:{port}{mfaRecoveryPath}?inOut=true{_sslParams}")
            .RouteId("http-mfa-recovery-get")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process(MfaCookieProcessors.ReadMfaStateCookie)
            .Process((e, ct) => MfaPageProcessors.RenderMfaRecoveryPage(e, ct, mfaRecoveryPath, mfaPath, _transportOptions))
            .Process(HttpIdentityProcessors.SerializeJsonResponse);

        From($"{_scheme}:POST:0.0.0.0:{port}{mfaRecoveryPath}?inOut=true{_sslParams}")
            .RouteId("http-mfa-recovery-post")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process(HttpIdentityProcessors.MapFormToBody)
            .Process(MfaCookieProcessors.ReadMfaStateCookie)
            .To(IdentityEndpoints.MfaRecovery)
            .Process((e, ct) => SessionCookieProcessors.WriteSessionCookie(e, ct, _ticketService, cookieMaxAge, secureCookie, sessionCookieName, sessionSameSite, useHostPrefix))
            .Process((e, ct) => MfaCookieProcessors.ClearMfaStateCookieOnSuccess(e, ct, secureCookie, CookieSameSiteMode.Strict, useHostPrefix))
            .Process((e, ct) => MfaPageProcessors.HandleMfaRecoveryResponse(e, ct, mfaRecoveryPath, mfaPath, _transportOptions))
            .Process(HttpIdentityProcessors.SerializeJsonResponse);

        // MFA challenge dispatch — POST sends OTP via SMS/Email, returns new mfa_state with embedded code.
        // AJAX endpoint (no session cookie set here — that happens after verify).
        var mfaChallengePath = mfaPath.TrimEnd('/') + "/challenge";
        From($"{_scheme}:POST:0.0.0.0:{port}{mfaChallengePath}?inOut=true{_sslParams}")
            .RouteId("http-mfa-challenge-post")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process(HttpIdentityProcessors.MapFormToBody)
            .Process(MfaCookieProcessors.ReadMfaStateCookie)
            .To(IdentityEndpoints.MfaChallenge)
            // Refresh __Host-redb.identity.mfa cookie with the new state issued by the challenge.
            .Process((e, ct) => MfaCookieProcessors.WriteMfaStateCookie(e, ct, secureCookie, CookieSameSiteMode.Strict, useHostPrefix, TimeSpan.FromMinutes(5)))
            .Process(HttpIdentityProcessors.SerializeJsonResponse);

        // B9 / BUG-9 — gated MFA method enumeration. Auth0-style: caller must present a
        // valid encrypted mfa_state (issued by login) to learn which factors are configured.
        var mfaMethodsPath = mfaPath.TrimEnd('/') + "/methods";
        From($"{_scheme}:POST:0.0.0.0:{port}{mfaMethodsPath}?inOut=true{_sslParams}")
            .RouteId("http-mfa-methods-post")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process(HttpIdentityProcessors.MapFormToBody)
            .To(IdentityEndpoints.MfaListMethods)
            .Process(HttpIdentityProcessors.SerializeJsonResponse);

        // Consent page — GET renders consent form, POST processes decision
        From($"{_scheme}:GET:0.0.0.0:{port}{consentPath}?inOut=true{_sslParams}")
            .RouteId("http-consent-get")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process((e, ct) => ConsentPageProcessors.RenderConsentPage(e, ct, consentPath, _transportOptions))
            .Process(HttpIdentityProcessors.SerializeJsonResponse);

        From($"{_scheme}:POST:0.0.0.0:{port}{consentPath}?inOut=true{_sslParams}")
            .RouteId("http-consent-post")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process((e, ct) => SessionCookieProcessors.ReadSessionCookie(e, ct, _ticketService, cookieMaxAge, sessionCookieName))
            .Process(HttpIdentityProcessors.MapFormToBody)
            .Process(ConsentPageProcessors.PrepareConsentBody)
            .To(IdentityEndpoints.ConsentGrant)
            .Process((e, ct) => ConsentPageProcessors.HandleConsentResponse(e, ct, _transportOptions))
            .Process(HttpIdentityProcessors.SerializeJsonResponse);

        // Userinfo — GET and POST with Bearer token. AttachBearerChallengeOnError adds
        // the WWW-Authenticate: Bearer challenge mandated by RFC 6750 §3 on any error
        // response (missing token, invalid token, etc.).
        From($"{_scheme}:GET:0.0.0.0:{port}/connect/userinfo?inOut=true{_sslParams}{ClientCorsParams()}")
            .RouteId("http-userinfo-get")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process(HttpIdentityProcessors.ExtractBearerToken)
            .To(IdentityEndpoints.Userinfo)
            .Process(HttpIdentityProcessors.MapOAuthErrorToHttpStatus)
            .Process(HttpIdentityProcessors.AttachBearerChallengeOnError)
            .Process(HttpIdentityProcessors.SerializeJsonResponse);

        From($"{_scheme}:POST:0.0.0.0:{port}/connect/userinfo?inOut=true{_sslParams}{ClientCorsParams()}")
            .RouteId("http-userinfo-post")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            // RFC 6750 §2.2 also allows the access token as a form-encoded body parameter, not just
            // the Authorization header. Without MapFormToBody the POST body never reached the
            // handler, so `access_token=…` in the body came back as "missing_token" (the OIDF suite
            // reports this as "does not appear to support access tokens passed in the POST body").
            // The header still wins when both are present — ExtractUserinfoRequestHandler only falls
            // back to it when the request carries no access_token parameter.
            .Process(HttpIdentityProcessors.MapFormToBody)
            .Process(HttpIdentityProcessors.ExtractBearerToken)
            .To(IdentityEndpoints.Userinfo)
            .Process(HttpIdentityProcessors.MapOAuthErrorToHttpStatus)
            .Process(HttpIdentityProcessors.AttachBearerChallengeOnError)
            .Process(HttpIdentityProcessors.SerializeJsonResponse);

        // Revocation — client-authenticated
        From($"{_scheme}:POST:0.0.0.0:{port}/connect/revocation?inOut=true{_sslParams}{ClientCorsParams()}")
            .RouteId("http-revoke")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process(HttpIdentityProcessors.MapHttpToIdentityHeaders)
            .Process(HttpIdentityProcessors.MapFormToBody)
            .To(IdentityEndpoints.Revoke)
            .Process(HttpIdentityProcessors.SerializeJsonResponse)
            .Process(HttpIdentityProcessors.AddNoStoreCacheHeaders); // RFC 7009 / 6749 §5.1

        // Introspection — client-authenticated
        From($"{_scheme}:POST:0.0.0.0:{port}/connect/introspect?inOut=true{_sslParams}{ClientCorsParams()}")
            .RouteId("http-introspect")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process(HttpIdentityProcessors.MapHttpToIdentityHeaders)
            .Process(HttpIdentityProcessors.MapFormToBody)
            .To(IdentityEndpoints.Introspect)
            .Process(HttpIdentityProcessors.MapOAuthErrorToHttpStatus)
            .Process(HttpIdentityProcessors.SerializeJsonResponse)
            .Process(HttpIdentityProcessors.AddNoStoreCacheHeaders); // RFC 7662 / 6749 §5.1

        // Logout — GET /connect/logout (OIDC RP-Initiated Logout §2: browser redirect)
        // ReadSessionCookie extracts userId from cookie so LogoutProcessor can revoke sessions.
        // Phase 9e: post_logout_redirect_uri validation goes through BrokeredPostLogoutRedirectValidator
        // (direct-vm broker call into Core). The validator is resolved at route-build time and
        // captured by the inline lambda below; null in test-fixture mode → falls back to "signed out".

        var validatePostLogout = _postLogoutValidator is null
            ? (Func<string, CancellationToken, Task<bool>>?)null
            : _postLogoutValidator.IsAllowedAsync;

        From($"{_scheme}:GET:0.0.0.0:{port}/connect/logout?inOut=true{_sslParams}{ClientCorsParams()}")
            .RouteId("http-logout-get")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process((e, ct) => SessionCookieProcessors.ReadSessionCookie(e, ct, _ticketService, cookieMaxAge, sessionCookieName))
            .Process(HttpIdentityProcessors.MapQueryToBody)
            .Process(HttpIdentityProcessors.PreservePostLogoutRedirectUri)
            .To(IdentityEndpoints.Logout)
            .Process((e, ct) => SessionCookieProcessors.ClearSessionCookie(e, ct, secureCookie, sessionCookieName, sessionSameSite, useHostPrefix))
            .Process((e, ct) => HttpIdentityProcessors.HandlePostLogoutRedirect(e, ct, _transportOptions, validatePostLogout))
            .Process(HttpIdentityProcessors.SerializeJsonResponse);

        // Logout — POST /connect/logout (form submission)
        From($"{_scheme}:POST:0.0.0.0:{port}/connect/logout?inOut=true{_sslParams}{ClientCorsParams()}")
            .RouteId("http-logout")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process((e, ct) => SessionCookieProcessors.ReadSessionCookie(e, ct, _ticketService, cookieMaxAge, sessionCookieName))
            .Process(HttpIdentityProcessors.MapFormToBody)
            .Process(HttpIdentityProcessors.PreservePostLogoutRedirectUri)
            .To(IdentityEndpoints.Logout)
            .Process((e, ct) => SessionCookieProcessors.ClearSessionCookie(e, ct, secureCookie, sessionCookieName, sessionSameSite, useHostPrefix))
            .Process((e, ct) => HttpIdentityProcessors.HandlePostLogoutRedirect(e, ct, _transportOptions, validatePostLogout))
            .Process(HttpIdentityProcessors.SerializeJsonResponse);

        // Dynamic Client Registration — POST /connect/register (RFC 7591)
        if (_transportOptions.Features.EnableDynamicRegistration)
        {
            From($"{_scheme}:POST:0.0.0.0:{port}{DynamicRegistrationPath}?inOut=true{_sslParams}{ClientCorsParams()}")
                .RouteId("http-dynamic-register")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
                .Process(HttpIdentityProcessors.ExtractBearerToken)
                .To(IdentityEndpoints.DynamicRegister)
                .Process(HttpIdentityProcessors.SerializeJsonResponse);

            // Z2 (RFC 7592): Client configuration endpoint — GET/PUT/DELETE /connect/register/{client_id}.
            // Single catch-all route; the op+id extractor derives operation and client_id from method+path.
            From($"{_scheme}:0.0.0.0:{port}{DynamicRegistrationPath}/{{**clientId}}?inOut=true{_sslParams}{ClientCorsParams()}")
                .RouteId("http-dynamic-register-manage")
                .Process(HttpIdentityProcessors.PropagateCorrelationId)
                .Process(HttpIdentityProcessors.ExtractBearerToken)
                .Process(HttpIdentityProcessors.ExtractDynamicRegistrationManagement)
                .To(IdentityEndpoints.DynamicRegisterManage)
                .Process(HttpIdentityProcessors.SerializeJsonResponse);
        }

        // Device Authorization — POST /connect/deviceauthorization (RFC 8628)
        if (_transportOptions.Features.EnableDeviceCodeFlow)
        {
            From($"{_scheme}:POST:0.0.0.0:{port}/connect/deviceauthorization?inOut=true{_sslParams}{ClientCorsParams()}")
                .RouteId("http-device")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
                .Process(HttpIdentityProcessors.MapHttpToIdentityHeaders)
                .Process(HttpIdentityProcessors.MapFormToBody)
                .To(IdentityEndpoints.Device)
                .Process(HttpIdentityProcessors.MapOAuthErrorToHttpStatus)
                .Process(HttpIdentityProcessors.SerializeJsonResponse)
                .Process(HttpIdentityProcessors.AddNoStoreCacheHeaders); // RFC 8628 / 6749 §5.1

            // End-User Verification — POST /connect/device/verify (RFC 8628 §3.3).
            // ExtractBearerToken is required for the BFF-relayed authentication path:
            // HandleVerificationRequestHandler accepts either form credentials (direct
            // host-UI flow) OR an Authorization: Bearer access_token (BFF-relayed flow).
            From($"{_scheme}:POST:0.0.0.0:{port}/connect/device/verify?inOut=true{_sslParams}")
                .RouteId("http-verification")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
                .Process(HttpIdentityProcessors.MapHttpToIdentityHeaders)
                .Process(HttpIdentityProcessors.ExtractBearerToken)
                .Process(HttpIdentityProcessors.MapFormToBody)
                .To(IdentityEndpoints.Verification)
                .Process(HttpIdentityProcessors.MapOAuthErrorToHttpStatus)
                .Process(HttpIdentityProcessors.SerializeJsonResponse);
        }
    }

    /// <summary>
    /// Discovery and JWKS endpoints (read-only, no auth required).
    /// </summary>
    /// <remarks>
    /// Exposes both OIDC Discovery 1.0 (<c>/.well-known/openid-configuration</c>) and
    /// RFC 8414 OAuth 2.0 Authorization Server Metadata
    /// (<c>/.well-known/oauth-authorization-server</c>). Both routes share the same
    /// document — the OIDC superset is a valid OAuth 2.0 metadata response per
    /// RFC 8414 §2 (additional fields are allowed).
    /// </remarks>
    private void ConfigureDiscoveryEndpoints(int port)
    {
        // OIDC Discovery 1.0
        BuildDiscoveryRoute(port, "/.well-known/openid-configuration", "http-discovery");

        // RFC 8414 — OAuth 2.0 Authorization Server Metadata (for non-OIDC clients)
        BuildDiscoveryRoute(port, "/.well-known/oauth-authorization-server", "http-discovery-oauth");

        From($"{_scheme}:GET:0.0.0.0:{port}/.well-known/jwks?inOut=true{_sslParams}{PublicCorsParams()}")
            .RouteId("http-jwks")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .To(IdentityEndpoints.Jwks)
            .Process(HttpIdentityProcessors.SerializeJsonResponse);
    }

    private void BuildDiscoveryRoute(int port, string path, string routeId)
    {
        var route = From($"{_scheme}:GET:0.0.0.0:{port}{path}?inOut=true{_sslParams}{PublicCorsParams()}")
            .RouteId(routeId)
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .To(IdentityEndpoints.Discovery);

        if (_transportOptions.Features.EnableDynamicRegistration)
        {
            var issuer = _transportOptions.Issuer.ToString().TrimEnd('/');
            route.Process((e, ct) =>
            {
                var body = e.HasOut ? e.Out!.Body : e.In.Body;
                if (body is IDictionary<string, object?> dict)
                    dict["registration_endpoint"] = $"{issuer}{DynamicRegistrationPath}";
                return Task.CompletedTask;
            });
        }

        route.Process(HttpIdentityProcessors.SerializeJsonResponse);
    }

    /// <summary>
    /// Management API using <see cref="RedbController"/>-based dispatch.
    /// All <c>/api/v1/identity/*</c> requests are handled by attribute-routed controllers.
    /// Bearer token authentication (via <see cref="IProcessor"/>) validates the access token
    /// and enforces the required management scope before request processing.
    /// </summary>
    private void ConfigureManagementApi(int port)
    {
        var registry = new ControllerRegistry();
        registry.RegisterController(typeof(ApplicationsController));
        registry.RegisterController(typeof(ConsentsController));
        registry.RegisterController(typeof(GroupsController));
        registry.RegisterController(typeof(ScopesController));
        registry.RegisterController(typeof(SessionsController));
        registry.RegisterController(typeof(MeSessionsController));
        registry.RegisterController(typeof(RevokedSidsController));
        registry.RegisterController(typeof(MeController));
        registry.RegisterController(typeof(MePasswordController));
        registry.RegisterController(typeof(PasswordRecoveryController));
        registry.RegisterController(typeof(AccountRegistrationController));
        registry.RegisterController(typeof(MeEmailVerifyController));
        registry.RegisterController(typeof(AccountEmailVerifyController));
        registry.RegisterController(typeof(MeChangeEmailController));
        registry.RegisterController(typeof(AccountChangeEmailController));
        registry.RegisterController(typeof(MeMfaController));
        registry.RegisterController(typeof(MeWebAuthnController));
        registry.RegisterController(typeof(MeConsentsController));
        registry.RegisterController(typeof(MeFederatedIdentitiesController));
        registry.RegisterController(typeof(TokensController));
        registry.RegisterController(typeof(UsersController));
        registry.RegisterController(typeof(MfaController));
        registry.RegisterController(typeof(AuditController));
        registry.RegisterController(typeof(ClaimMappersController));
        registry.RegisterController(typeof(ClaimScopesController));
        registry.RegisterController(typeof(ClaimDefinitionsController));
        registry.RegisterController(typeof(RolesController));
        registry.RegisterController(typeof(WebhooksController));
        registry.RegisterController(typeof(FederationProvidersController));
        registry.RegisterController(typeof(ImpersonationController));
        registry.RegisterController(typeof(SigningKeysController));

        // SCIM discovery endpoints under management API path (RFC 7644 §4) — unauthenticated
        var scimDiscoveryRegistry = new ControllerRegistry();
        scimDiscoveryRegistry.RegisterController(typeof(ScimDiscoveryController));

        From($"{_scheme}:GET:0.0.0.0:{port}/api/v1/identity/scim/v2/ServiceProviderConfig?inOut=true{_sslParams}")
            .RouteId("http-management-scim-discovery-spc")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process(HttpIdentityProcessors.StripManagementPrefix)
            .Process(ScimHttpProcessors.StripScimPrefix)
            .RedbHttpController(scimDiscoveryRegistry)
            .Process(ScimHttpProcessors.SerializeScimJsonResponse);

        From($"{_scheme}:GET:0.0.0.0:{port}/api/v1/identity/scim/v2/ResourceTypes?inOut=true{_sslParams}")
            .RouteId("http-management-scim-discovery-rt")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process(HttpIdentityProcessors.StripManagementPrefix)
            .Process(ScimHttpProcessors.StripScimPrefix)
            .RedbHttpController(scimDiscoveryRegistry)
            .Process(ScimHttpProcessors.SerializeScimJsonResponse);

        // Single-resource discovery. These existed on the public /scim/v2 surface but not here, so a
        // provisioning client pointed at the management base URL — which is how Okta / Entra are
        // actually configured: one base URL, and they walk ResourceTypes then fetch each Schema by
        // id — got a 404 on the very first schema it asked for. Same registry, same controller; only
        // the route was missing.
        From($"{_scheme}:GET:0.0.0.0:{port}/api/v1/identity/scim/v2/ResourceTypes/{{**path}}?inOut=true{_sslParams}")
            .RouteId("http-management-scim-discovery-rt-id")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process(HttpIdentityProcessors.StripManagementPrefix)
            .Process(ScimHttpProcessors.StripScimPrefix)
            .RedbHttpController(scimDiscoveryRegistry)
            .Process(ScimHttpProcessors.MapScimResponseToHttpStatus)
            .Process(ScimHttpProcessors.SerializeScimJsonResponse);

        From($"{_scheme}:GET:0.0.0.0:{port}/api/v1/identity/scim/v2/Schemas?inOut=true{_sslParams}")
            .RouteId("http-management-scim-discovery-schemas")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process(HttpIdentityProcessors.StripManagementPrefix)
            .Process(ScimHttpProcessors.StripScimPrefix)
            .RedbHttpController(scimDiscoveryRegistry)
            .Process(ScimHttpProcessors.SerializeScimJsonResponse);

        From($"{_scheme}:GET:0.0.0.0:{port}/api/v1/identity/scim/v2/Schemas/{{**path}}?inOut=true{_sslParams}")
            .RouteId("http-management-scim-discovery-schema-id")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process(HttpIdentityProcessors.StripManagementPrefix)
            .Process(ScimHttpProcessors.StripScimPrefix)
            .RedbHttpController(scimDiscoveryRegistry)
            .Process(ScimHttpProcessors.MapScimResponseToHttpStatus)
            .Process(ScimHttpProcessors.SerializeScimJsonResponse);

        var route = From($"{_scheme}:0.0.0.0:{port}/api/v1/identity/{{**path}}?inOut=true{_sslParams}")
            .RouteId("http-management-api");

        // Bearer-auth runs in Core's RouteContext via direct-vm. Synchronous, same
        // exchange — equivalent to inline Process(...) but keeps Http facade free of
        // any reference to Core's internal processor type.
        route.To(IdentityEndpoints.AuthManagement);

        route.Process(GranularScopeGuardProcessor.Enforce)
            .Process(HttpIdentityProcessors.StripManagementPrefix)
            .RedbHttpController(registry)
            .Process(HttpIdentityProcessors.MapManagementErrorToHttpStatus);
    }

    /// <summary>
    /// SCIM 2.0 provisioning API (RFC 7644).
    /// Discovery endpoints are unauthenticated (RFC 7643 §5).
    /// Resource endpoints (Users, Groups) require SCIM auth.
    /// </summary>
    private void ConfigureScimApi(int port)
    {
        // Discovery endpoints — no auth required (RFC 7643 §5)
        var discoveryRegistry = new ControllerRegistry();
        discoveryRegistry.RegisterController(typeof(ScimDiscoveryController));

        From($"{_scheme}:GET:0.0.0.0:{port}/scim/v2/ServiceProviderConfig?inOut=true{_sslParams}")
            .RouteId("http-scim-discovery-spc")
            .Process((e, ct) => { System.Diagnostics.Debug.WriteLine("[SCIM-DISCOVERY-SPC] Route matched!"); return Task.CompletedTask; })
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process(ScimHttpProcessors.StripScimPrefix)
            .RedbHttpController(discoveryRegistry)
            .Process(ScimHttpProcessors.SerializeScimJsonResponse);

        From($"{_scheme}:GET:0.0.0.0:{port}/scim/v2/ResourceTypes?inOut=true{_sslParams}")
            .RouteId("http-scim-discovery-rt")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process(ScimHttpProcessors.StripScimPrefix)
            .RedbHttpController(discoveryRegistry)
            .Process(ScimHttpProcessors.SerializeScimJsonResponse);

        From($"{_scheme}:GET:0.0.0.0:{port}/scim/v2/ResourceTypes/{{**path}}?inOut=true{_sslParams}")
            .RouteId("http-scim-discovery-rt-id")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process(ScimHttpProcessors.StripScimPrefix)
            .RedbHttpController(discoveryRegistry)
            .Process(ScimHttpProcessors.MapScimResponseToHttpStatus)
            .Process(ScimHttpProcessors.SerializeScimJsonResponse);

        From($"{_scheme}:GET:0.0.0.0:{port}/scim/v2/Schemas?inOut=true{_sslParams}")
            .RouteId("http-scim-discovery-schemas")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process(ScimHttpProcessors.StripScimPrefix)
            .RedbHttpController(discoveryRegistry)
            .Process(ScimHttpProcessors.SerializeScimJsonResponse);

        From($"{_scheme}:GET:0.0.0.0:{port}/scim/v2/Schemas/{{**path}}?inOut=true{_sslParams}")
            .RouteId("http-scim-discovery-schema-id")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process(ScimHttpProcessors.StripScimPrefix)
            .RedbHttpController(discoveryRegistry)
            .Process(ScimHttpProcessors.MapScimResponseToHttpStatus)
            .Process(ScimHttpProcessors.SerializeScimJsonResponse);

        // Resource endpoints — auth required
        var scimRegistry = new ControllerRegistry();
        scimRegistry.RegisterController(typeof(ScimUsersController));
        scimRegistry.RegisterController(typeof(ScimGroupsController));
        if (_transportOptions.Features.EnableScimBulk)
            scimRegistry.RegisterController(typeof(ScimBulkController));

        var route = From($"{_scheme}:0.0.0.0:{port}/scim/v2/{{**path}}?inOut=true{_sslParams}")
            .RouteId("http-scim-api")
            .Process((e, ct) => { System.Diagnostics.Debug.WriteLine("[SCIM-CATCHALL] Route matched!"); return Task.CompletedTask; });

        // SCIM bearer-auth runs in Core's RouteContext via direct-vm.
        route.To(IdentityEndpoints.AuthScim);

        route.Process(ScimHttpProcessors.StripScimPrefix)
            .RedbHttpController(scimRegistry)
            .Process(ScimHttpProcessors.MapScimResponseToHttpStatus)
            .Process(ScimHttpProcessors.SerializeScimJsonResponse);
    }

    /// <summary>
    /// B1 — emergency-admin bootstrap endpoint <c>POST /internal/bootstrap-admin</c>.
    /// Mounted on the management port (<see cref="HttpTransportOptions.ManagementPort"/>),
    /// outside the regular <c>/api/v1/identity/</c> base path so that operators can firewall
    /// it independently. No bearer-token auth: protection is via the
    /// <c>X-Bootstrap-Secret</c> header validated by the underlying processor with
    /// <see cref="System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(System.ReadOnlySpan{byte}, System.ReadOnlySpan{byte})"/>.
    /// CORS is intentionally disabled — bootstrap is a back-channel admin tool, never
    /// invoked from a browser.
    /// </summary>
    private void ConfigureBootstrapEndpoint(int port)
    {
        From($"{_scheme}:POST:0.0.0.0:{port}/internal/bootstrap-admin?inOut=true{_sslParams}")
            .RouteId("http-bootstrap-admin")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .To(IdentityEndpoints.BootstrapAdmin)
            .Process(HttpIdentityProcessors.SerializeJsonResponse);
    }

    /// <summary>
    /// Federation endpoints: external-login (challenge) and callback.
    /// Maps browser redirects to <c>direct-vm://identity-federation-*</c> routes.
    /// </summary>
    private void ConfigureFederationEndpoints(int port)
    {
        var cookieMaxAge = _transportOptions.SessionCookieLifetime;
        var secureCookie = _transportOptions.Issuer.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase);
        var callbackPath = _transportOptions.Http.FederationCallbackPath;
        var issuer = _transportOptions.Issuer.ToString().TrimEnd('/');
        var bindingCookieName = _transportOptions.BindingCookieName;
        var cookieOpts = _transportOptions.Cookies;
        var sessionCookieName = cookieOpts.SessionCookieName;
        var sessionSameSite = cookieOpts.SessionSameSite;
        var bindingSameSite = cookieOpts.BindingSameSite;
        var useHostPrefix = cookieOpts.UseHostPrefix;

        // GET /connect/external-login?provider=xxx&returnUrl=yyy → redirect to IdP
        From($"{_scheme}:GET:0.0.0.0:{port}/connect/external-login?inOut=true{_sslParams}")
            .RouteId("http-federation-challenge")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process((e, ct) =>
            {
                HttpIdentityProcessors.MapQueryToBody(e, ct);
                var body = e.In.Body as IDictionary<string, object?>;
                body ??= new Dictionary<string, object?>();
                body["callbackUrl"] = $"{issuer}{callbackPath}";
                e.In.Body = body;
                // C9: hand cookie-formatting hints to FederationHttpProcessors so the
                // binding cookie comes out with the same flags the rest of identity uses.
                e.Properties["federation-binding-samesite"] = bindingSameSite;
                e.Properties["federation-binding-host-prefix"] = useHostPrefix;
                e.Properties["federation-binding-secure"] = secureCookie;
                return Task.CompletedTask;
            })
            .To(IdentityEndpoints.FederationChallenge)
            .Process(FederationHttpProcessors.HandleChallengeRedirect)
            .Process(HttpIdentityProcessors.SerializeJsonResponse);

        // GET /connect/federation/callback?code=xxx&state=yyy → token exchange + session
        From($"{_scheme}:GET:0.0.0.0:{port}{callbackPath}?inOut=true{_sslParams}")
            .RouteId("http-federation-callback")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process((e, ct) =>
            {
                HttpIdentityProcessors.MapQueryToBody(e, ct);
                var body = e.In.Body as IDictionary<string, object?>;
                body ??= new Dictionary<string, object?>();
                body["callbackUrl"] = $"{issuer}{callbackPath}";
                e.In.Body = body;
                e.Properties["federation-binding-samesite"] = bindingSameSite;
                e.Properties["federation-binding-host-prefix"] = useHostPrefix;
                e.Properties["federation-binding-secure"] = secureCookie;
                return Task.CompletedTask;
            })
            .Process((e, ct) => FederationHttpProcessors.ExtractBindingCookie(e, ct, bindingCookieName))
            .To(IdentityEndpoints.FederationCallback)
            .Process((e, ct) => SessionCookieProcessors.WriteSessionCookie(e, ct, _ticketService, cookieMaxAge, secureCookie, sessionCookieName, sessionSameSite, useHostPrefix))
            .Process((e, ct) => FederationHttpProcessors.HandleCallbackResponse(e, ct, bindingCookieName))
            .Process(HttpIdentityProcessors.SerializeJsonResponse);
    }

    /// <summary>
    /// Public read-only listing of federation providers safe for anonymous callers.
    /// Drives the federation sign-in buttons on third-party UIs (incl. our own
    /// <c>redb.Identity.Web</c> BFF) without forcing them to mirror the server-side
    /// <c>FederationProviders</c> configuration. The projection deliberately strips
    /// <c>ClientSecret</c>, <c>Authority</c>, scope list, and any other field that
    /// could leak provider configuration.
    /// </summary>
    private void ConfigurePublicFederationProvidersEndpoint(int port, string routeIdSuffix)
    {
        From($"{_scheme}:GET:0.0.0.0:{port}/api/v1/identity/federation-providers/public?inOut=true{_sslParams}")
            .RouteId($"http-federation-providers-public-{routeIdSuffix}")
            .Process(HttpIdentityProcessors.PropagateCorrelationId)
            .Process((e, ct) =>
            {
                // Skip providers that are still on placeholder credentials —
                // showing them on /login leads users into a 401 / Google
                // "OAuth client was not found" path that looks like a server
                // bug. Once the operator fills in the real ClientId, the
                // provider re-appears automatically (no restart needed
                // beyond config reload).
                static bool IsPlaceholder(string? value)
                    => string.IsNullOrWhiteSpace(value)
                       || string.Equals(value, "REPLACE_ME", StringComparison.OrdinalIgnoreCase)
                       || value.Contains("REPLACE_ME", StringComparison.OrdinalIgnoreCase);

                var providers = _transportOptions.FederationProviders
                    .Where(p => !IsPlaceholder(p.ClientId)
                                && !IsPlaceholder(p.Authority))
                    .OrderBy(p => p.Priority)
                    .ThenBy(p => p.ProviderId, StringComparer.Ordinal)
                    .Select(p => new PublicFederationProviderDescriptor(
                        ProviderId: p.ProviderId,
                        DisplayName: p.DisplayName,
                        Kind: p.Kind,
                        Priority: p.Priority))
                    .ToArray();

                e.Out = new Message();
                e.Out.Body = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(
                    providers,
                    IdentityWireProfiles.OAuthOptions);
                e.Out.Headers[HttpHeaders.ResponseContentType] = "application/json; charset=utf-8";
                e.Out.Headers[HttpHeaders.ResponseCode] = 200;
                // Browsers may safely cache the public list for 60s; revalidate after that.
                e.Out.Headers["Cache-Control"] = "public, max-age=60";
                return Task.CompletedTask;
            });
    }
}
