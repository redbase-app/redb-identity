using System.Data.Common;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;
using redb.Core;
using redb.Core.Services;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.OpenIddict;
using redb.Identity.Core.Routes.Processors;
using redb.Identity.Core.Services;
using redb.Route;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.Mail;
using redb.Route.RedbCore.Models;
using redb.Route.RedbCore.Repositories;
using redb.Route.RedbCore.Transactions;
using redb.Route.Transactions;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes;

/// <summary>
/// Core route builder for the redb Identity Server.
/// Registers all 15 direct-vm:// endpoints with error handling, throttle, and event dispatch.
/// </summary>
public class IdentityCoreRouteBuilder : RouteBuilder
{
    private readonly IServiceProvider _sp;
    private readonly string? _redbName;
    private readonly RedbIdentityOptions _options;
    private readonly IdentityAuditOptions _auditOptions;
    private readonly IProcessor? _managementAuth;
    private readonly IProcessor? _scimAuth;

    public IdentityCoreRouteBuilder(
        IServiceProvider sp,
        IOptions<RedbIdentityOptions> options,
        IOptions<IdentityAuditOptions>? auditOptions = null,
        IProcessor? managementAuth = null,
        IProcessor? scimAuth = null)
    {
        _sp = sp;
        _options = options.Value;
        _auditOptions = auditOptions?.Value ?? new IdentityAuditOptions();
        _redbName = _options.RedbInstanceName;
        _managementAuth = managementAuth;
        _scimAuth = scimAuth;
    }

    protected override void Configure()
    {
        var handler = _sp.GetRequiredService<RedbRouteOpenIddictServerHandler>();
        var timeProvider = _sp.GetService<TimeProvider>() ?? TimeProvider.System;

        // ── Builder-level error handling ──

        // DB transient errors → retry 3x with exponential backoff
        OnException<DbException>()
            .MaximumRedeliveries(3)
            .RedeliveryDelay(TimeSpan.FromMilliseconds(200))
            .UseExponentialBackOff()
            .BackOffMultiplier(2.0)
            .Handled()
            .LogStackTrace()
            .Process(e =>
            {
                var outMsg = EnsureOut(e);
                outMsg.Body = ErrorResponse("server_error", "Database temporarily unavailable.");
                outMsg.Headers["redbHttp.ResponseCode"] = 503;
            });

        // Catch-all: unexpected errors → generic server_error, no internals leaked
        OnException<Exception>()
            .Handled()
            .LogStackTrace()
            .Process(e =>
            {
                var outMsg = EnsureOut(e);
                outMsg.Body = ErrorResponse("server_error", "An unexpected error occurred.");
                outMsg.Headers["redbHttp.ResponseCode"] = 500;
            });

        // ── Protocol endpoints ──

        // C2 — single shared trusted-proxy resolver. Sanitizes redbHttp.RemoteAddress on
        // routes consumed by per-IP throttling / per-IP lockout BEFORE any of those see it.
        // Secure-by-default: when ReverseProxies.TrustForwardedFor is false (default) the
        // processor is a no-op. See ReverseProxyOptions for trust model.
        var trustedProxy = new TrustedProxyResolverProcessor(
            _options.ReverseProxies,
            _sp.GetService<ILoggerFactory>()?.CreateLogger<TrustedProxyResolverProcessor>());

        // C1 — Per-IP / per-(IP+username) rate limit. Built only when enabled in config so
        // that disabled-installations have zero overhead. Camel-style conditional pipeline:
        // the route chain is split at trustedProxy and the optional Process(...) calls are
        // appended via local IRouteDefinition references before the OnException/business
        // processors are attached.
        var rlEnabled = _options.RateLimit.Enabled;
        // E5: security-channel logger — rate-limit breaches and per-(IP+user) failure
        // ceilings are audit-class signals and flow through RedbIdentity.Security so
        // downstream log-routing can mirror them to SIEM/audit sinks.
        var securityLogger = _sp.GetService<ILoggerFactory>() is { } lf
            ? Security.IdentitySecurityLog.CreateLogger(lf)
            : null;
        var rlLogger = securityLogger;
        var perIpThrottle = rlEnabled
            ? new RateLimitProcessor(
                _sp,
                bucketTag: "any",
                limitSelector: o => o.PerIpPerMinute,
                windowSelector: _ => TimeSpan.FromMinutes(1),
                logger: rlLogger)
            : null;
        var loginFailureRecorder = rlEnabled
            ? new LoginFailureRecorderProcessor(
                _sp,
                securityLogger)
            : null;

        // 1. Token (OAuth error handling + throttle + WireTap). Writes are atomic at the
        // OpenIddict store level — RedbTokenStore / RedbAuthorizationStore each run their
        // own short tx on a DI-scoped IRedbService, NOT on the per-exchange one a
        // hypothetical WithRedbTx would wrap. A route-level wrap just held a SQLite writer
        // lock for the duration of Argon2id verify + the whole OpenIddict pipeline (~30s
        // observed), starving every other writer in the process for no atomicity benefit.
        var tokenRoute = From(IdentityEndpoints.Token)
            .RouteId(IdentityEndpoints.RouteIds.Token)
            .Process(trustedProxy);
        if (perIpThrottle is not null) tokenRoute = tokenRoute.Process(perIpThrottle);
        tokenRoute
            .OnException<InvalidOperationException>()
                .OnWhen(e => IsOAuthError(e.Exception))
                .Handled()
                .Process(MapOAuthExceptionToRfc6749Response)
            .EndOnException()
            .Throttle(
                ExtractClientIdForThrottle,
                _options.TokenThrottleMaxPerPeriod,
                _options.TokenThrottlePeriod)
                .RejectOnOverflow()
            // F3: emit `identity.token-request` metric (count + latency histogram) and a
            // matching OTEL span. Static step-name keeps Prometheus cardinality bounded.
            .Traced("identity.token-request")
                .Metered("identity.token-request", new TokenEndpointProcessor(handler, timeProvider))
            .EndTraced()
            .WireTap(IdentityEndpoints.Events);

        // 2. Authorize (WireTap). Writes (auth-code row) go through OpenIddict's authorization
        // store on its own DI-scoped IRedbService — atomicity is at the store level, not the
        // route. Route-level redb-tx wrap removed (see Token endpoint note).
        From(IdentityEndpoints.Authorize)
            .RouteId(IdentityEndpoints.RouteIds.Authorize)
            .Process(new AuthorizeEndpointProcessor(handler))
            .WireTap(IdentityEndpoints.Events);

        // 3. Userinfo (read-only, no WireTap)
        From(IdentityEndpoints.Userinfo)
            .RouteId(IdentityEndpoints.RouteIds.Userinfo)
            .Process(new UserinfoEndpointProcessor(handler));

        // 4. Introspect (DoTry/DoCatch expired tokens, read-only).
        // H6 (RFC 7662): emits TokenIntrospected audit event for every well-formed call,
        // so the route DOES WireTap to events even though it does not mutate state itself.
        From(IdentityEndpoints.Introspect)
            .RouteId(IdentityEndpoints.RouteIds.Introspect)
            .DoTry()
                .Process(new IntrospectionEndpointProcessor(handler))
            .DoCatch<SecurityTokenExpiredException>()
                .Process(e => { e.Out ??= e.In; e.Out.Body = new { active = false }; })
            .End()
            .WireTap(IdentityEndpoints.Events);

        // 5. Revoke (WireTap). Revocation writes go through OpenIddict's token store on its
        // own DI-scoped IRedbService — atomicity is at the store level, not the route.
        // Route-level redb-tx wrap removed (see Token endpoint note).
        From(IdentityEndpoints.Revoke)
            .RouteId(IdentityEndpoints.RouteIds.Revoke)
            .Process(new RevocationEndpointProcessor(handler, timeProvider))
            .WireTap(IdentityEndpoints.Events);

        // 6. Discovery (read-only, no WireTap)
        From(IdentityEndpoints.Discovery)
            .RouteId(IdentityEndpoints.RouteIds.Discovery)
            .Process(new DiscoveryEndpointProcessor(handler));

        // 7. JWKS (read-only, no WireTap)
        //    When the PROPS signing-key store is enabled, the JWKS is served LIVE from the
        //    store on every request so admin /signing-keys/rotate and /retire reflect
        //    immediately — see LiveJwksProcessor. Otherwise we fall back to OpenIddict's
        //    static JWKS handler that picks from the frozen options.SigningCredentials list.
        if (_options.UsePropsSigningKeyStore)
        {
            var signingKeyStore = _sp.GetRequiredService<redb.Identity.Core.Keys.ISigningKeyStore>();
            From(IdentityEndpoints.Jwks)
                .RouteId(IdentityEndpoints.RouteIds.Jwks)
                .Process(new LiveJwksProcessor(signingKeyStore));
        }
        else
        {
            From(IdentityEndpoints.Jwks)
                .RouteId(IdentityEndpoints.RouteIds.Jwks)
                .Process(new JwksEndpointProcessor(handler));
        }

        // 8. Device Authorization (RFC 8628). Device-code persist + state update both go
        // through OpenIddict stores (DI-scoped IRedbService) — atomicity is at the store
        // level. Route-level redb-tx wrap removed (see Token endpoint note).
        if (_options.Features.EnableDeviceCodeFlow)
        {
            From(IdentityEndpoints.Device)
                .RouteId(IdentityEndpoints.RouteIds.Device)
                .Process(new DeviceEndpointProcessor(handler))
                .WireTap(IdentityEndpoints.Events);

            // 9. End-User Verification (RFC 8628 §3.3).
            From(IdentityEndpoints.Verification)
                .RouteId(IdentityEndpoints.RouteIds.Verification)
                .Process(new VerificationEndpointProcessor(handler))
                .WireTap(IdentityEndpoints.Events);
        }

        // Pushed Authorization Requests (RFC 9126 / Z6). PAR persists a one-time request_uri
        // via OpenIddict's authorization store on its own DI-scoped IRedbService — same
        // pattern as Authorize. Throttled per-IP same as Token because PAR is a back-channel
        // POST that can be brute-forced. Route-level redb-tx wrap removed (see Token note).
        if (_options.Features.EnablePushedAuthorization)
        {
            var parRoute = From(IdentityEndpoints.PushedAuthorization)
                .RouteId(IdentityEndpoints.RouteIds.PushedAuthorization)
                .Process(trustedProxy);
            if (perIpThrottle is not null) parRoute = parRoute.Process(perIpThrottle);
            parRoute
                .Throttle(
                    ExtractClientIdForThrottle,
                    _options.TokenThrottleMaxPerPeriod,
                    _options.TokenThrottlePeriod)
                    .RejectOnOverflow()
                .Traced("identity.par-request")
                    .Metered("identity.par-request", new PushedAuthorizationEndpointProcessor(handler))
                .EndTraced()
                .WireTap(IdentityEndpoints.Events);
        }

        // Dynamic Client Registration (RFC 7591). E2: Idempotency-Key cache placed BEFORE
        // Throttle so replays do not consume IP quota. NOTE on tx: DynamicRegistrationProcessor
        // ONLY calls _context.GetIdentityService<IOpenIddictApplicationManager>() — the
        // application persist + secret-hash both flow through OpenIddict's DI-scoped
        // RedbApplicationStore (a different IRedbService, different SqliteRedbConnection)
        // than the per-exchange one any route-level WithRedbTx wraps. The wrap was therefore
        // a no-op atomicity-wise but held the SQLite single-writer lock during the
        // ~30-second OpenIddict pipeline, causing every concurrent writer to time out with
        // SQLITE_BUSY (the failure mode the diag run captured). Removed.
        if (_options.Features.EnableDynamicRegistration)
        {
            var dynRegRoute = From(IdentityEndpoints.DynamicRegister)
                .RouteId(IdentityEndpoints.RouteIds.DynamicRegister);
            var dynRegPre = BuildIdempotencyPre("dynamic-register");
            if (dynRegPre is not null) dynRegRoute = dynRegRoute.Process(dynRegPre);
            dynRegRoute = dynRegRoute
                .Throttle(
                    e => e.In.GetHeader<string>("redbHttp.RemoteAddress") ?? "anonymous",
                    _options.DynamicRegistrationThrottleMaxPerPeriod,
                    _options.DynamicRegistrationThrottlePeriod)
                    .RejectOnOverflow()
                .Process(new DynamicRegistrationProcessor(
                    Context!,
                    _sp.GetRequiredService<IOptions<RedbIdentityOptions>>(),
                    timeProvider: null,
                    loggerFactory: _sp.GetService<ILoggerFactory>()));
            var dynRegPost = BuildIdempotencyPost();
            if (dynRegPost is not null) dynRegRoute = dynRegRoute.Process(dynRegPost);
            dynRegRoute.WireTap(IdentityEndpoints.Events);

            // Z2 (RFC 7592): Client configuration endpoint. Read/Update/Delete gated by the
            // registration_access_token issued at DCR time. ClientRegistrationManagementProcessor
            // does its primary read+write via OpenIddict's ApplicationManager (DI-scoped,
            // separate IRedbService → separate SqliteRedbConnection); the per-exchange IRedbService
            // at line 153 is used only for minor side-effects. A route-level WithRedbTx held the
            // SQLite writer lock on the per-exchange connection while OpenIddict's manager
            // opened a SECOND connection on the same DB file for the actual DELETE — self-
            // deadlock, 5s busy_timeout × ~7 retries = ~34s observed on RFC 7592 DELETE. Same
            // pattern as account/register. Atomicity at OpenIddict store level is preserved.
            From(IdentityEndpoints.DynamicRegisterManage)
                .RouteId(IdentityEndpoints.RouteIds.DynamicRegisterManage)
                .Process(new ClientRegistrationManagementProcessor(Context!, _redbName))
                .WireTap(IdentityEndpoints.Events);
        }

        // 10. Login (credential verification → session cookie set by HTTP facade).
        // LoginProcessor + LoginFailureRecorder both resolve their IRedbService through _sp
        // (DI scope), NOT through the per-exchange context — route-level redb-tx wrap covers
        // a different connection. Removed; otherwise it would hold a SQLite writer lock for
        // the full Argon2id verify + auto-rehash CPU window (~2-4s) for no atomicity benefit.
        var loginRoute = From(IdentityEndpoints.Login)
            .RouteId(IdentityEndpoints.RouteIds.Login)
            .Process(trustedProxy);
        if (perIpThrottle is not null) loginRoute = loginRoute.Process(perIpThrottle);
        // F3: identity.login span+meter — covers credential check + failure-recorder. The
        // LoginFailureRecorder is intentionally inside the same span so brute-force lockout
        // increments are visible in distributed traces.
        loginRoute = loginRoute
            .Traced("identity.login")
                .Metered("identity.login", new LoginProcessor(_sp));
        if (loginFailureRecorder is not null) loginRoute = loginRoute.Process(loginFailureRecorder);
        loginRoute.EndTraced().WireTap(IdentityEndpoints.Events);

        // 11. MFA TOTP verification (code → session with mfaVerified)
        // B3: dedup by (jti, code) — defends against retransmits / captured-request replay,
        // legitimate retry with a different code still passes through.
        // The B1 row-lock + FailedAttempts++ inside the processor remain the brute-force guard.
        var mfaIdempotentRepo = new RedbIdempotentRepository(
            _sp.GetRequiredService<IServiceScopeFactory>(),
            new RedbIdempotentOptions
            {
                ProcessorName = "identity-mfa-verify",
                Ttl = TimeSpan.FromMinutes(15) // matches MfaState TTL ceiling
            });
        var mfaStateProtector = _sp.GetRequiredService<MfaStateProtector>();

        // MfaVerifyProcessor resolves IRedbService through _sp (DI scope), so a route-level
        // redb-tx wrap on the per-exchange connection covered nothing — removed (see Token note).
        From(IdentityEndpoints.MfaVerify)
            .RouteId(IdentityEndpoints.RouteIds.MfaVerify)
            .Process(trustedProxy)
            .IdempotentConsumer(e =>
            {
                var body = e.In.Body as IDictionary<string, object?>;
                var token = body?.TryGetValue("mfa_state", out var s) == true ? s?.ToString() : null;
                var code = body?.TryGetValue("code", out var c) == true ? c?.ToString() : null;
                if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(code))
                    return string.Empty; // bad request — let processor return invalid_request
                var st = mfaStateProtector.Unprotect(token);
                if (st is null || st.Jti == Guid.Empty)
                    return string.Empty; // expired/invalid/legacy state — let processor handle
                return $"mfa-verify:{st.Jti:N}:{code}";
            }, mfaIdempotentRepo, skipDuplicate: true)
            // F3: identity.mfa-verify — security-critical step, span enables forensic timeline
            // reconstruction; histogram detects slow TOTP-secret-protector decryption.
            .Traced("identity.mfa-verify")
                .Metered("identity.mfa-verify", new MfaVerifyProcessor(_sp))
            .EndTraced()
            .WireTap(IdentityEndpoints.Events);

        // 11b. MFA challenge dispatch (SMS/Email OTP send)
        From(IdentityEndpoints.MfaChallenge)
            .RouteId(IdentityEndpoints.RouteIds.MfaChallenge)
            .Process(trustedProxy)
            .Process(new MfaChallengeProcessor(_sp))
            .WireTap(IdentityEndpoints.Events);

        // 11c. B9 / BUG-9 — Auth0-style gated method enumeration.
        From(IdentityEndpoints.MfaListMethods)
            .RouteId(IdentityEndpoints.RouteIds.MfaListMethods)
            .Process(trustedProxy)
            .Process(new MfaListMethodsProcessor(_sp));

        // 11d. Phase 9d — cross-context broker queries served to other Tsak contexts
        //      (currently only the redb.Identity.Http facade in 'identity.http').
        //      All three are read-only, in-memory after warm-up, and bypass throttle/audit
        //      because the caller is a trusted in-process facade, not external traffic.
        From(IdentityEndpoints.CorsCheck)
            .RouteId(IdentityEndpoints.RouteIds.CorsCheck)
            .Process(new CorsCheckProcessor(_sp));

        From(IdentityEndpoints.ValidatePostLogoutRedirect)
            .RouteId(IdentityEndpoints.RouteIds.ValidatePostLogoutRedirect)
            .Process(new ValidatePostLogoutRedirectProcessor(_sp));

        From(IdentityEndpoints.MfaMethodsFromState)
            .RouteId(IdentityEndpoints.RouteIds.MfaMethodsFromState)
            .Process(new MfaMethodsFromStateProcessor(_sp));

        // 12. MFA recovery code verification — marks recovery code consumed.
        // MfaRecoveryProcessor resolves IRedbService through _sp (DI scope) — route-level
        // redb-tx wrap removed (see Token note).
        From(IdentityEndpoints.MfaRecovery)
            .RouteId(IdentityEndpoints.RouteIds.MfaRecovery)
            .Process(trustedProxy)
            .Process(new MfaRecoveryProcessor(_sp))
            .WireTap(IdentityEndpoints.Events);

        // 13. MFA management (setup, confirm, disable, status)
        // B8: RequireSelfOrAdminProcessor enforces self-vs-admin so a token with the
        // self-service scope (identity:account) cannot mutate another user's MFA. When
        // called via direct-vm without an HTTP auth context the processor bypasses (see
        // its docs) — keeps internal flows / tests working.
        // E2: Idempotency-Key cache placed AFTER mfaSelfOrAdmin so authorization is always
        // re-checked on replays (a revoked token must not unlock cached responses).
        var mfaSelfOrAdmin = new RequireSelfOrAdminProcessor(
            _options.ManagementScope,
            _options.AccountScope,
            securityLogger);

        // MfaSetupProcessor resolves IRedbService through _sp (DI scope), so a route-level
        // redb-tx wrap on the per-exchange connection covered nothing — removed (see Token
        // note). Idempotency pre/post below still apply (cache lookup is independent of tx).
        var mfaManageRoute = From(IdentityEndpoints.MfaManage)
            .RouteId(IdentityEndpoints.RouteIds.MfaManage)
            .Process(mfaSelfOrAdmin);
        var mfaManagePre = BuildIdempotencyPre("mfa-manage");
        if (mfaManagePre is not null) mfaManageRoute = mfaManageRoute.Process(mfaManagePre);
        mfaManageRoute = mfaManageRoute.Process(new MfaSetupProcessor(_sp));
        var mfaManagePost = BuildIdempotencyPost();
        if (mfaManagePost is not null) mfaManageRoute = mfaManageRoute.Process(mfaManagePost);
        mfaManageRoute.WireTap(IdentityEndpoints.Events);

        // ── Management endpoints (all with WireTap) ──

        // 8. Manage Apps — E2: Idempotency-Key cache (no redb-tx wrap).
        // ApplicationManagementProcessor uses 6 OpenIddict service calls (DI-scoped, separate
        // IRedbService instance) — a route-level redb-tx held the per-exchange writer lock
        // while OpenIddict's manager opened a SECOND SqliteRedbConnection for the actual
        // CreateAsync/UpdateAsync/DeleteAsync, eating ~34s observed in admin POST /applications.
        // wrapInRedbTx:false keeps idempotency caching but skips redb-tx.
        WithIdempotentTx(
            From(IdentityEndpoints.ManageApps).RouteId(IdentityEndpoints.RouteIds.ManageApps),
            "manage-apps",
            new ApplicationManagementProcessor(Context!, _redbName),
            wrapInRedbTx: false)
            .WireTap(IdentityEndpoints.Events);

        // 9. Manage Scopes — E1: tx-wrapped. E2: Idempotency-Key cache.
        WithIdempotentTx(
            From(IdentityEndpoints.ManageScopes).RouteId(IdentityEndpoints.RouteIds.ManageScopes),
            "manage-scopes",
            new ScopeManagementProcessor(Context!, _redbName))
            .WireTap(IdentityEndpoints.Events);

        // 10. Manage Users — E1: tx-wrapped (multi-row writes for users + props). E2: Idempotency-Key cache.
        WithIdempotentTx(
            From(IdentityEndpoints.ManageUsers).RouteId(IdentityEndpoints.RouteIds.ManageUsers),
            "manage-users",
            new UserManagementProcessor(Context!, _redbName))
            .WireTap(IdentityEndpoints.Events);

        // 11. Manage Tokens — E1: tx-wrapped (revoke/cleanup batches). E2: Idempotency-Key cache.
        var backgroundDeletion = _sp.GetService<IBackgroundDeletionService>();
        var cleanupProcessor = new TokenCleanupProcessor(Context!, _sp.GetRequiredService<IOptions<RedbIdentityOptions>>(), _redbName, backgroundDeletion);
        WithIdempotentTx(
            From(IdentityEndpoints.ManageTokens).RouteId(IdentityEndpoints.RouteIds.ManageTokens),
            "manage-tokens",
            new TokenManagementProcessor(Context!, _redbName, cleanupProcessor))
            .WireTap(IdentityEndpoints.Events);

        // 12. Manage Groups — E1: tx-wrapped. E2: Idempotency-Key cache.
        WithIdempotentTx(
            From(IdentityEndpoints.ManageGroups).RouteId(IdentityEndpoints.RouteIds.ManageGroups),
            "manage-groups",
            new GroupManagementProcessor(Context!, _redbName, backgroundDeletion))
            .WireTap(IdentityEndpoints.Events);

        // 13. Manage Consents — E1: tx-wrapped. E2: Idempotency-Key cache.
        WithIdempotentTx(
            From(IdentityEndpoints.ManageConsents).RouteId(IdentityEndpoints.RouteIds.ManageConsents),
            "manage-consents",
            new ConsentManagementProcessor(Context!, _redbName))
            .WireTap(IdentityEndpoints.Events);

        // 13b. H9 — Audit query (read-only, no tx/idempotency/WireTap).
        From(IdentityEndpoints.ManageAudit)
            .RouteId(IdentityEndpoints.RouteIds.ManageAudit)
            .Process(new AuditQueryProcessor(Context!, _redbName));

        // 13b-iv. Signing-key lifecycle (list / rotate / retire). Mounted unconditionally
        // so the admin surface is the same regardless of whether the PROPS store is enabled
        // — when disabled, the processor just returns an empty list / "no active store"
        // error. WireTap fires SigningKeyRotated / SigningKeyRetired audit events.
        {
            var signingKeyStore = _sp.GetService<redb.Identity.Core.Keys.ISigningKeyStore>();
            if (signingKeyStore is not null)
            {
                From(IdentityEndpoints.ManageSigningKeys)
                    .RouteId(IdentityEndpoints.RouteIds.ManageSigningKeys)
                    .Process(new SigningKeysManagementProcessor(signingKeyStore))
                    .WireTap(IdentityEndpoints.Events);
            }
        }

        // 13b-i. N7-3 — Admin impersonation overlay (start/stop). Does not mint tokens;
        // emits audit events only. No tx / no idempotency cache (purely an audit beacon).
        From(IdentityEndpoints.ManageImpersonation)
            .RouteId(IdentityEndpoints.RouteIds.ManageImpersonation)
            .Process(new ImpersonationManagementProcessor(Context!, _redbName))
            .WireTap(IdentityEndpoints.Events);

        // 13c. H5 — Manage Claim Mappers (declarative claims). E1: tx, E2: Idempotency-Key cache.
        WithIdempotentTx(
            From(IdentityEndpoints.ManageClaimMappers).RouteId(IdentityEndpoints.RouteIds.ManageClaimMappers),
            "manage-claim-mappers",
            new ClaimMapperManagementProcessor(Context!, _redbName))
            .WireTap(IdentityEndpoints.Events);

        // 13d. H5 — Manage Claim Scopes (reusable mapper bundles + Application↔Scope assignments).
        WithIdempotentTx(
            From(IdentityEndpoints.ManageClaimScopes).RouteId(IdentityEndpoints.RouteIds.ManageClaimScopes),
            "manage-claim-scopes",
            new ClaimScopeManagementProcessor(Context!, _redbName))
            .WireTap(IdentityEndpoints.Events);

        // 13e. S2 — Manage Claim Definitions (schema with required + type + regex).
        WithIdempotentTx(
            From(IdentityEndpoints.ManageClaimDefinitions).RouteId(IdentityEndpoints.RouteIds.ManageClaimDefinitions),
            "manage-claim-definitions",
            new ClaimDefinitionsManagementProcessor(Context!, _redbName, _sp.GetRequiredService<ILoggerFactory>().CreateLogger<ClaimDefinitionsManagementProcessor>()))
            .WireTap(IdentityEndpoints.Events);

        // 13f. B.3 — Manage Roles (registry + assignments).
        WithIdempotentTx(
            From(IdentityEndpoints.ManageRoles).RouteId(IdentityEndpoints.RouteIds.ManageRoles),
            "manage-roles",
            new RoleManagementProcessor(Context!, _redbName, _sp.GetRequiredService<ILoggerFactory>().CreateLogger<RoleManagementProcessor>()))
            .WireTap(IdentityEndpoints.Events);

        // 13g. W1 — Manage Webhook subscriptions (admin CRUD).
        WithIdempotentTx(
            From(IdentityEndpoints.ManageWebhooks).RouteId(IdentityEndpoints.RouteIds.ManageWebhooks),
            "manage-webhooks",
            new WebhookManagementProcessor(Context!, _redbName, _sp.GetRequiredService<ILoggerFactory>().CreateLogger<WebhookManagementProcessor>()))
            .WireTap(IdentityEndpoints.Events);

        // 14. Logout — E1: tx-wrapped (revokes session + tokens).
        var logoutLogger = _sp.GetRequiredService<ILoggerFactory>().CreateLogger<LogoutProcessor>();
        var oidcServerOptions = _sp.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>();
        WithRedbTx(From(IdentityEndpoints.Logout)
            .RouteId(IdentityEndpoints.RouteIds.Logout))
            .Process(new LogoutProcessor(Context!, oidcServerOptions, _redbName, logoutLogger))
            .WireTap(IdentityEndpoints.Events);

        // 14b. Consent grant (user-facing approval from consent page) — E1: tx-wrapped.
        WithRedbTx(From(IdentityEndpoints.ConsentGrant)
            .RouteId(IdentityEndpoints.RouteIds.ConsentGrant))
            .Process(new ConsentGrantProcessor(Context!, _redbName))
            .WireTap(IdentityEndpoints.Events);

        // 15. Manage Sessions — E1: tx-wrapped. E2: Idempotency-Key cache.
        WithIdempotentTx(
            From(IdentityEndpoints.ManageSessions).RouteId(IdentityEndpoints.RouteIds.ManageSessions),
            "manage-sessions",
            new SessionManagementProcessor(Context!, _redbName))
            .WireTap(IdentityEndpoints.Events);

        // 15a. W6-0: Backchannel revoked-sids list — `add` and `since` operations.
        // E1: tx-wrapped. E2: Idempotency-Key cache (RPs may retry add on transient errors).
        WithIdempotentTx(
            From(IdentityEndpoints.RevokedSids).RouteId(IdentityEndpoints.RouteIds.RevokedSids),
            "revoked-sids",
            new RevokedSidsManagementProcessor(
                Context!,
                _sp.GetRequiredService<IOptions<RedbIdentityOptions>>(),
                _redbName,
                timeProvider))
            .WireTap(IdentityEndpoints.Events);

        // 15b. /me/sessions — H3-SSO (v1.0 DoD §6 scoped-subset). Self-service list/revoke
        // of the caller's own sessions. User id is derived from the authenticated token
        // subject; request body is NOT trusted for user targeting. Supports both
        // `identity:manage` and `identity:account` scopes — admins calling the /me endpoint
        // get their own sessions, identical to non-admin callers. Cross-user administration
        // remains on the admin route above.
        WithRedbTx(
            From(IdentityEndpoints.MeSessions).RouteId(IdentityEndpoints.RouteIds.MeSessions))
            .Process(new MeSessionsProcessor(Context!, _redbName))
            .WireTap(IdentityEndpoints.Events);

        // 15c. /me/profile + /me/password + /me/mfa + /me/consents — H3 (v1.0 DoD §6).
        // Self-service "complete SSO account console" surface. Each processor derives
        // the user id from the authenticated token subject (NEVER from the request
        // body) so that admin callers using their own access token can only manage
        // their own profile through these routes. Cross-user administration stays on
        // the corresponding admin endpoints (/users, /mfa, /users/{id}/consents).
        // MeProfile / MePassword / Password* / EmailVerify* / ChangeEmail* :
        // these processors take BOTH per-exchange IRedbService AND _sp (DI scope) for stores
        // like IPasswordHistoryStore / IEmailVerificationTokenStore / IChangeEmailTokenStore /
        // ISigningKeyStore that internally call _scopeFactory.CreateAsyncScope() and resolve
        // their own IRedbService — a SECOND SqliteRedbConnection on the same DB file. A route-
        // level WithRedbTx held the writer lock on conn A while the store opened conn B for
        // its INSERT/UPDATE, causing 5 s busy_timeout × ~7 retries = ~34s on every invocation
        // (confirmed for AccountRegister via [Diag-AR] anchor: 34,204 ms in historyStore.RecordAsync
        // alone). Per-exchange atomicity for the processor's own writes is preserved
        // (each redb.SaveAsync still uses one short tx) — only the cross-store atomicity goes,
        // which was never enforceable anyway because the store ran on a separate connection.
        From(IdentityEndpoints.MeProfile).RouteId(IdentityEndpoints.RouteIds.MeProfile)
            .Process(new MeProfileProcessor(Context!, _redbName))
            .WireTap(IdentityEndpoints.Events);

        From(IdentityEndpoints.MePassword).RouteId(IdentityEndpoints.RouteIds.MePassword)
            .Process(new MePasswordProcessor(Context!, _redbName))
            .WireTap(IdentityEndpoints.Events);

        // N-4 (Session C): anonymous password-recovery endpoints. Anti-enumeration is
        // enforced inside the processor (always 200/success). trustedProxy + perIpThrottle
        // are layered upstream so brute-force enumeration of the email field is rate-limited
        // per real client IP (X-Forwarded-For respected only behind trusted proxies).
        var passwordForgotRoute = From(IdentityEndpoints.PasswordForgot)
            .RouteId(IdentityEndpoints.RouteIds.PasswordForgot)
            .Process(trustedProxy);
        if (perIpThrottle is not null) passwordForgotRoute = passwordForgotRoute.Process(perIpThrottle);
        passwordForgotRoute
            .Process(new PasswordForgotProcessor(Context!, _sp, _redbName))
            .WireTap(IdentityEndpoints.Events);

        var passwordResetRoute = From(IdentityEndpoints.PasswordReset)
            .RouteId(IdentityEndpoints.RouteIds.PasswordReset)
            .Process(trustedProxy);
        if (perIpThrottle is not null) passwordResetRoute = passwordResetRoute.Process(perIpThrottle);
        passwordResetRoute
            .Process(new PasswordResetProcessor(Context!, _sp, _redbName))
            .WireTap(IdentityEndpoints.Events);

        // N-4 (Session C, N4-6): e-mail-verification routes. Feature-gated by
        // RedbIdentityOptions.EmailVerification.Enabled (default OFF) so existing
        // deployments without an IEmailNotificationChannel keep the same route count.
        // /me/verify-email/send is authenticated (Me* convention); /account/verify-email/confirm
        // is anonymous and rate-limited identically to password-recovery.
        if (_options.EmailVerification.Enabled)
        {
            From(IdentityEndpoints.MeEmailVerifySend).RouteId(IdentityEndpoints.RouteIds.MeEmailVerifySend)
                .Process(new EmailVerifySendProcessor(Context!, _sp, _redbName))
                .WireTap(IdentityEndpoints.Events);

            var emailVerifyConfirmRoute = From(IdentityEndpoints.EmailVerifyConfirm)
                .RouteId(IdentityEndpoints.RouteIds.EmailVerifyConfirm)
                .Process(trustedProxy);
            if (perIpThrottle is not null)
                emailVerifyConfirmRoute = emailVerifyConfirmRoute.Process(perIpThrottle);
            emailVerifyConfirmRoute
                .Process(new EmailVerifyConfirmProcessor(Context!, _sp, _redbName))
                .WireTap(IdentityEndpoints.Events);
        }

        // N-4 (Session E, N4-7): strict verify-then-commit change-of-e-mail routes.
        // Feature-gated by RedbIdentityOptions.ChangeEmail.Enabled (default OFF).
        // /me/change-email/request is authenticated (Me* convention); /change-email/confirm
        // is anonymous and rate-limited identically to password-recovery / verify-email.
        if (_options.ChangeEmail.Enabled)
        {
            From(IdentityEndpoints.MeChangeEmailRequest).RouteId(IdentityEndpoints.RouteIds.MeChangeEmailRequest)
                .Process(new ChangeEmailRequestProcessor(Context!, _sp, _redbName))
                .WireTap(IdentityEndpoints.Events);

            var changeEmailConfirmRoute = From(IdentityEndpoints.ChangeEmailConfirm)
                .RouteId(IdentityEndpoints.RouteIds.ChangeEmailConfirm)
                .Process(trustedProxy);
            if (perIpThrottle is not null)
                changeEmailConfirmRoute = changeEmailConfirmRoute.Process(perIpThrottle);
            changeEmailConfirmRoute
                .Process(new ChangeEmailConfirmProcessor(Context!, _sp, _redbName))
                .WireTap(IdentityEndpoints.Events);
        }

        // N-3 (sub-step N3-7): anonymous self-service account registration. Feature-gated
        // by RedbIdentityOptions.Registration.Enabled (default OFF) so corporate / SCIM-
        // provisioned deployments do not silently expose a public sign-up surface. When
        // enabled the route shares the same trustedProxy + perIpThrottle envelope as the
        // password-recovery routes so brute-force enumeration of the e-mail field via
        // duplicate-account probes is rate-limited per real client IP.
        // AccountRegister write-path uses two distinct IRedbService instances:
        // (1) the per-exchange one for CreateUserAsync + SaveAsync(propsObj), AND
        // (2) PropsPasswordHistoryStore's own CreateAsyncScope() resolution for the
        //     password-history record + cleanup query.
        // A route-level WithRedbTx wraps only (1) on its per-exchange connection but holds
        // the SQLite writer lock for the whole route — (2) opens a SECOND SqliteConnection
        // on the same DB file and self-deadlocks against (1), eating ~30s of busy_timeout
        // retries before the swallow-catch in AccountRegisterProcessor finally lets the
        // route return 200. Confirmed via [Diag-AR] timing anchors: 34,204ms spent in
        // historyStore.RecordAsync alone, every other step <10ms. Atomicity loss is
        // benign here: CreateUserAsync is atomic in itself; SaveAsync(propsObj) failing
        // afterwards leaves the user with a valid _users row but no OIDC props (login
        // still works); password history is best-effort by contract (swallowed catch).
        if (_options.Registration.Enabled)
        {
            var accountRegisterRoute = From(IdentityEndpoints.AccountRegister)
                .RouteId(IdentityEndpoints.RouteIds.AccountRegister)
                .Process(trustedProxy);
            if (perIpThrottle is not null)
                accountRegisterRoute = accountRegisterRoute.Process(perIpThrottle);
            accountRegisterRoute
                .Process(new AccountRegisterProcessor(Context!, _sp, _redbName))
                .WireTap(IdentityEndpoints.Events);
        }

        // MeMfa / MeWebAuthn / MfaWebAuthn — all three processors resolve IRedbService
        // through _sp (DI scope), so a route-level redb-tx wrap on the per-exchange
        // connection covered nothing. Removed (see Token note).
        From(IdentityEndpoints.MeMfa).RouteId(IdentityEndpoints.RouteIds.MeMfa)
            .Process(new MeMfaProcessor(_sp))
            .WireTap(IdentityEndpoints.Events);

        // MFA-3: WebAuthn routes are gated on the master switch. When disabled the controller
        // surface still binds (returns 404 if no route) but no in-process route exists.
        if (_options.WebAuthn.Enabled)
        {
            From(IdentityEndpoints.MeWebAuthn).RouteId(IdentityEndpoints.RouteIds.MeWebAuthn)
                .Process(new MeWebAuthnProcessor(_sp))
                .WireTap(IdentityEndpoints.Events);

            From(IdentityEndpoints.MfaWebAuthn).RouteId(IdentityEndpoints.RouteIds.MfaWebAuthn)
                .Process(new WebAuthnAssertProcessor(_sp))
                .WireTap(IdentityEndpoints.Events);
        }

        WithRedbTx(
            From(IdentityEndpoints.MeConsents).RouteId(IdentityEndpoints.RouteIds.MeConsents))
            .Process(new MeConsentsProcessor(Context!, _redbName))
            .WireTap(IdentityEndpoints.Events);

        // H8 (DoD §4 gap (b)/(d)): self-service federated identity link/unlink/list.
        WithRedbTx(
            From(IdentityEndpoints.MeFederatedIdentities).RouteId(IdentityEndpoints.RouteIds.MeFederatedIdentities))
            .Process(new MeFederatedIdentitiesProcessor(Context!, _sp, _redbName))
            .WireTap(IdentityEndpoints.Events);

        // H8 (DoD §4 gap (e)): admin CRUD over PROPS-stored federation providers.
        // E1 tx + E2 Idempotency-Key cache, mirroring the ClaimMapperManagement wiring above.
        WithIdempotentTx(
            From(IdentityEndpoints.ManageFederationProviders).RouteId(IdentityEndpoints.RouteIds.ManageFederationProviders),
            "manage-federation-providers",
            new FederationProviderManagementProcessor(Context!, _redbName))
            .WireTap(IdentityEndpoints.Events);

        // ── SCIM 2.0 endpoints (RFC 7644) ──

        if (_options.Features.EnableScim)
        {
            // E1: SCIM provisioning is RFC 7644 mutation API — tx-wrapped end-to-end.
            // E2: Idempotency-Key cache for safe retries.
            WithIdempotentTx(
                From(IdentityEndpoints.ScimUsers).RouteId(IdentityEndpoints.RouteIds.ScimUsers),
                "scim-users",
                new ScimUserProcessor(Context!, _redbName))
                .WireTap(IdentityEndpoints.Events);

            WithIdempotentTx(
                From(IdentityEndpoints.ScimGroups).RouteId(IdentityEndpoints.RouteIds.ScimGroups),
                "scim-groups",
                new ScimGroupProcessor(Context!, _redbName, backgroundDeletion: backgroundDeletion))
                .WireTap(IdentityEndpoints.Events);

            // H1 (RFC 7644 §3.7): SCIM Bulk endpoint. Each inner op is dispatched to its
            // own SCIM route (which is itself WithIdempotentTx), so partial-success
            // semantics fall out for free — the bulk processor never runs inside a single
            // outer transaction.
            if (_options.Features.EnableScimBulk)
            {
                From(IdentityEndpoints.ScimBulk).RouteId(IdentityEndpoints.RouteIds.ScimBulk)
                    .Process(new ScimBulkProcessor(Context!,
                        _options.ScimBulkMaxOperations,
                        _options.ScimBulkMaxPayloadSize))
                    .WireTap(IdentityEndpoints.Events);
            }
        }

        // ── Federation endpoints (OIDC external IdP) ──

        if (_options.Features.EnableFederation && _options.FederationProviders.Count > 0)
        {
            From(IdentityEndpoints.FederationChallenge)
                .RouteId(IdentityEndpoints.RouteIds.FederationChallenge)
                .Process(new FederationChallengeProcessor(_sp))
                .WireTap(IdentityEndpoints.Events);

            // Federation callback creates/updates federated user + identity link.
            // FederationCallbackProcessor takes ONLY IServiceProvider (no IRouteContext);
            // it does ALL its DB work via `_sp.CreateScope().GetService<IRedbService>()` —
            // a SECOND SqliteRedbConnection on the same DB file. A route-level WithRedbTx
            // wrapped the per-exchange connection while the processor's scope opened conn B
            // for user provisioning + session creation, self-deadlocking at ~15s (HTTP
            // client gives up first) — observed in demo_federation_{e2e,github}.ps1 as
            // "callback returned 0" (connection abort, no provisioning happened). Same
            // pure-group-A pattern as Token/Login/etc.
            From(IdentityEndpoints.FederationCallback)
                .RouteId(IdentityEndpoints.RouteIds.FederationCallback)
                .Process(new FederationCallbackProcessor(_sp))
                .WireTap(IdentityEndpoints.Events);
        }

        // ── Cross-context auth processors (consumed by the HTTP facade module) ──
        //
        // The HTTP facade lives in a separate Tsak context (.tpkg) with its own ALC
        // and cannot construct ManagementBearerAuthProcessor itself (the type is
        // internal to Core and depends on scoped OpenIddict validation services).
        // Exposing the auth step as direct-vm consumers lets the facade call them
        // inline via .To(...) — synchronous, zero-copy, same exchange — and removes
        // the need for any cross-module static state.

        if (_managementAuth is not null)
            From(IdentityEndpoints.AuthManagement)
                .RouteId(IdentityEndpoints.RouteIds.AuthManagement)
                .Process(_managementAuth);

        if (_scimAuth is not null)
            From(IdentityEndpoints.AuthScim)
                .RouteId(IdentityEndpoints.RouteIds.AuthScim)
                .Process(_scimAuth);

        // ── B1: emergency-admin bootstrap ──
        // Always registered (even when disabled) so the HTTP facade does not 404 at the
        // route-dispatch layer; the processor itself short-circuits with a 404-shaped body
        // when BootstrapOptions.Enabled=false. Wrapped in WithRedbTx so any failure between
        // scope/group/user/membership/client/flag rolls back atomically — the spec's primary
        // acceptance criterion. WireTap to events for audit (ClientRegistered + bootstrap
        // marker in event-data).
        var bootstrapOpts = _sp.GetRequiredService<IOptions<RedbIdentityOptions>>();
        var bootstrapLoggerFactory = _sp.GetService<ILoggerFactory>();
        WithRedbTx(From(IdentityEndpoints.BootstrapAdmin)
            .RouteId(IdentityEndpoints.RouteIds.BootstrapAdmin))
            .Process(new BootstrapAdminProcessor(Context!, bootstrapOpts, timeProvider, bootstrapLoggerFactory))
            .WireTap(IdentityEndpoints.Events);

        // ── Event dispatch + Audit ──

        // 16. Events consumer (receives WireTap copies → audit targets)
        var evtLogger = _sp.GetRequiredService<ILoggerFactory>()
            .CreateLogger<EventDispatchProcessor>();
        var eventsRoute = From(IdentityEndpoints.Events)
            .RouteId(IdentityEndpoints.RouteIds.Events)
            .Process(new EventDispatchProcessor(evtLogger, _auditOptions, timeProvider));

        // R1: built-in relational sink — always-on when audit is enabled and PersistToProps=true
        // (option name retained for backwards compat; actual storage is now the flat
        // `identity_audit_log` table created at boot by IdentityAuditLogTableInitListener,
        // not REDB props). Authoritative local trail for `GET /api/v1/identity/audit`;
        // external multicast targets run afterwards and are independent.
        if (_auditOptions is { Enabled: true, PersistToProps: true })
        {
            var sinkLogger = _sp.GetRequiredService<ILoggerFactory>()
                .CreateLogger<AuditRelationalSinkProcessor>();
            eventsRoute = eventsRoute.Process(new AuditRelationalSinkProcessor(Context!, sinkLogger, _redbName));
        }

        // W1: outbound webhook delivery — runs after the audit sink so the
        // local trail is durable BEFORE we fan out to subscribers. Delivery
        // goes through redb.Route's IProducerTemplate so the subscription URL
        // is opaque (https://, kafka://, amqp://, …) — Core stays
        // transport-agnostic; the producer the URI resolves to picks the wire.
        //
        // ProducerTemplate is constructed LAZILY by the processor on first
        // event (using IRouteContext captured at processor-construction time).
        // Eager construction here would null-deref ProducerTemplate.ctor for
        // tests that pass a null context to Configure — those are pure
        // route-shape probes that never actually deliver.
        var webhookLogger = _sp.GetRequiredService<ILoggerFactory>()
            .CreateLogger<WebhookDeliveryProcessor>();
        eventsRoute = eventsRoute.Process(new WebhookDeliveryProcessor(
            Context!, _redbName, webhookLogger));

        // Chain to audit multicast if audit is enabled with active targets
        var enabledTargets = _auditOptions is { Enabled: true }
            ? _auditOptions.Targets.Where(t => t.Enabled && !string.IsNullOrEmpty(t.Uri)).ToArray()
            : [];

        if (enabledTargets.Length > 0)
        {
            // Boundary: typed IdentityEvent → JSON bytes for external transports
            // (Kafka/Elasticsearch/RabbitMQ/log). The PROPS sink above runs first on the typed
            // payload; only after that we wire-encode for multicast targets that don't
            // negotiate ContentType themselves.
            eventsRoute
                .Marshal(typeof(redb.Route.Serialization.JsonMessageSerializer))
                .Multicast(enabledTargets.Select(t => t.Uri).ToArray());
        }

        // ── Token cleanup timer ──

        // 17. Periodic cleanup of expired tokens and orphaned authorizations
        var cleanupInterval = _options.TokenCleanupInterval;
        if (cleanupInterval > TimeSpan.Zero && cleanupInterval != Timeout.InfiniteTimeSpan)
        {
            From(TimerDsl.Every("token-cleanup")
                    .Period((int)cleanupInterval.TotalMilliseconds)
                    .Delay(30_000))
                .RouteId("identity-token-cleanup")
                .Cluster(true) // A5: leader-only when Tsak.Cluster.Enabled=true; silently ignored in standalone
                .Process(cleanupProcessor)
                .WireTap(IdentityEndpoints.Events);
        }

        // ── Session cleanup timer ──

        // 18. Periodic cleanup of revoked sessions older than retention
        var sessionCleanupInterval = _options.SessionCleanupInterval;
        if (sessionCleanupInterval > TimeSpan.Zero && sessionCleanupInterval != Timeout.InfiniteTimeSpan)
        {
            var sessionCleanupProcessor = new SessionCleanupProcessor(
                Context!, _sp.GetRequiredService<IOptions<RedbIdentityOptions>>(), _redbName, backgroundDeletion);

            From(TimerDsl.Every("session-cleanup")
                    .Period((int)sessionCleanupInterval.TotalMilliseconds)
                    .Delay(60_000))
                .RouteId("identity-session-cleanup")
                .Cluster(true) // A5: leader-only when Tsak.Cluster.Enabled=true; silently ignored in standalone
                .Process(sessionCleanupProcessor)
                .WireTap(IdentityEndpoints.Events);
        }

        // ── Revoked-SIDs cleanup timer (W6-0) ──

        // 18a. Periodic cleanup of expired entries in the backchannel revoked-sids list.
        // Runs leader-only on the timer; soft-deletes via IBackgroundDeletionService when
        // available (cluster-safe claim pattern), otherwise direct hard-delete.
        var revokedSidsCleanupInterval = _options.RevokedSidsCleanupInterval;
        if (revokedSidsCleanupInterval > TimeSpan.Zero && revokedSidsCleanupInterval != Timeout.InfiniteTimeSpan)
        {
            var revokedSidsCleanupProcessor = new RevokedSidsCleanupProcessor(
                Context!, _sp.GetRequiredService<IOptions<RedbIdentityOptions>>(),
                _redbName, backgroundDeletion, timeProvider);

            From(TimerDsl.Every("revoked-sids-cleanup")
                    .Period((int)revokedSidsCleanupInterval.TotalMilliseconds)
                    .Delay(75_000))
                .RouteId(IdentityEndpoints.RouteIds.RevokedSidsCleanup)
                .Cluster(true) // A5: leader-only when Tsak.Cluster.Enabled=true; silently ignored in standalone
                .Process(revokedSidsCleanupProcessor)
                .WireTap(IdentityEndpoints.Events);
        }

        // ── MFA OTP cleanup timer (B3) ──

        // 18b. Periodic cleanup of expired MfaOtpProps rows (SMS/Email OTP server-side store).
        // Verify already rejects expired rows at read time; this timer is purely storage hygiene.
        var mfaOtpCleanupInterval = _options.MfaOtpCleanupInterval;
        if (mfaOtpCleanupInterval > TimeSpan.Zero && mfaOtpCleanupInterval != Timeout.InfiniteTimeSpan)
        {
            var mfaOtpCleanupProcessor = new MfaOtpCleanupProcessor(
                Context!, _redbName, backgroundDeletion);

            From(TimerDsl.Every("mfa-otp-cleanup")
                    .Period((int)mfaOtpCleanupInterval.TotalMilliseconds)
                    .Delay(90_000))
                .RouteId("identity-mfa-otp-cleanup")
                .Cluster(true) // A5: leader-only when Tsak.Cluster.Enabled=true; silently ignored in standalone
                .Process(mfaOtpCleanupProcessor)
                .WireTap(IdentityEndpoints.Events);
        }

        // ── MFA-3: WebAuthn consumed-challenge cleanup timer ──

        // 18c. Periodic cleanup of WebAuthnConsumedChallengeProps rows past their TTL.
        // Replay protection is enforced at consume time by the unique index on ChallengeHash;
        // this timer is purely storage hygiene. Gated on the master WebAuthn switch.
        if (_options.WebAuthn.Enabled)
        {
            var webAuthnCleanupInterval = _options.WebAuthn.ChallengeCleanupInterval;
            if (webAuthnCleanupInterval > TimeSpan.Zero && webAuthnCleanupInterval != Timeout.InfiniteTimeSpan)
            {
                var webAuthnCleanupProcessor = new WebAuthnConsumedChallengeCleanupProcessor(
                    Context!, _redbName, backgroundDeletion);

                From(TimerDsl.Every("webauthn-challenge-cleanup")
                        .Period((int)webAuthnCleanupInterval.TotalMilliseconds)
                        .Delay(120_000))
                    .RouteId("identity-mfa-webauthn-challenge-cleanup")
                    .Cluster(true)
                    .Process(webAuthnCleanupProcessor)
                    .WireTap(IdentityEndpoints.Events);
            }
        }

        // ── DataProtection XML key-ring refresh timer ──

        // 19. A1: per-replica reload of RedbXmlRepository snapshot from PROPS storage.
        // NOT .Cluster(true) — EVERY node must refresh its own local snapshot to pick up
        // keys rotated by other replicas; leader-only would defeat the purpose (other
        // nodes would still encrypt with stale keys until restart).
        var xmlRefreshInterval = _options.XmlRepositoryRefreshInterval;
        if (xmlRefreshInterval > TimeSpan.Zero && xmlRefreshInterval != Timeout.InfiniteTimeSpan)
        {
            From(TimerDsl.Every("identity-xml-refresh")
                    .Period((int)xmlRefreshInterval.TotalMilliseconds)
                    .Delay(120_000))
                .RouteId("identity-xml-refresh")
                .Process(new DataProtection.XmlRepositoryRefreshProcessor(_sp));
        }

        // ── N-4 (Session C): outbound transactional e-mail backbone ──

        // 20. SMTP send route. The SmtpEmailNotificationChannel publishes here; the route
        // forwards to MailKit via the redb.Route.Mail DSL. Built only when SMTP is
        // explicitly enabled — hosts that ship their own channel (in-memory tests,
        // SendGrid satellite, …) simply leave Smtp.Enabled = false and replace the
        // IEmailNotificationChannel registration.
        var smtp = _options.Smtp;
        if (smtp.Enabled && !string.IsNullOrWhiteSpace(smtp.Host))
        {
            var smtpBuilder = Smtp.Send(smtp.Host)
                .Port(smtp.Port)
                .Security(smtp.Security ?? "None")
                .From(smtp.FromAddress)
                .ContentType("text/html")
                .AlternativeBody()
                // Disconnect after every send. Transactional Identity mail is sparse
                // (forgot-password, verify-email) and pooled long-lived SMTP connections
                // routinely fail against test servers (GreenMail SO_TIMEOUT=30s) and real
                // relays alike — the cost of an extra TCP handshake per mail is dwarfed by
                // the operational headache of "Service shutting down" replays mid-flight.
                .Disconnect();
            if (!string.IsNullOrWhiteSpace(smtp.Username))
                smtpBuilder = smtpBuilder.Username(smtp.Username);
            if (!string.IsNullOrWhiteSpace(smtp.Password))
                smtpBuilder = smtpBuilder.Password(smtp.Password);
            if (smtp.SkipCertificateValidation)
                smtpBuilder = smtpBuilder.SkipCertificateValidation();

            From(IdentityEndpoints.EmailSend)
                .RouteId(IdentityEndpoints.RouteIds.EmailSend)
                .To(smtpBuilder)
                .WireTap(IdentityEndpoints.Events);
        }
    }

    // ── Helpers ──

    /// <summary>
    /// E1: Wraps a route in <c>redb</c> transaction boundary so that all writes performed
    /// during route execution commit/rollback atomically at the standard
    /// <c>TransactedProcessor</c> route boundary. Idempotent — safe to call once per route.
    /// Uses the configured <see cref="RedbIdentityOptions.RedbInstanceName"/> when present.
    /// </summary>
    /// <summary>
    /// E1: Wraps a route in a <c>redb</c> transaction boundary so that all writes performed
    /// during route execution commit/rollback atomically at the standard
    /// <c>TransactedProcessor</c> route boundary.
    /// <para>
    /// Requires <see cref="RedbIdentityOptions.RedbInstanceName"/> to be configured. Only the
    /// <b>named</b> resolution path is safe for transactions: it gives every exchange its own
    /// per-exchange scoped <see cref="IRedbService"/> (see
    /// <see cref="redb.Route.RedbCore.Extensions.RedbRouteExtensions.GetRedbService(IRouteContext, string, IExchange?)"/>),
    /// so the transaction never bleeds across concurrent exchanges. The anonymous singleton
    /// <c>IRedbService</c> is shared and would serialize all in-flight requests onto a single
    /// connection, so we deliberately no-op when the name is missing (typically in unit tests
    /// that intentionally skip the named-factory registration).
    /// </para>
    /// </summary>
    private IRouteDefinition WithRedbTx(IRouteDefinition route)
    {
        if (string.IsNullOrEmpty(_redbName))
            return route; // No named per-exchange scope → cannot safely open a route-level tx.

        // IMPORTANT: use TransactionPolicy.Suppress (not the default Required).
        //
        // We still need the surrounding TransactedProcessor — it is what calls Commit/Rollback
        // on the RedbTransactedAction registered by BeginRedbTransaction(). But we do NOT want
        // it to create an ambient System.Transactions.TransactionScope, because Npgsql auto-
        // enlists the connection in any ambient scope and NpgsqlRedbConnection.BeginTransactionAsync()
        // explicitly rejects opening an explicit Npgsql tx while Transaction.Current is non-null.
        //
        // Suppress gives us: TransactedProcessor wrapper (commit/rollback boundary) +
        // Transaction.Current == null inside (so explicit redb tx works). Identity endpoints
        // are single-DB so we don't need distributed-tx semantics anyway.
        return route.Transacted(TransactionPolicy.Suppress)
                    .BeginRedbTransaction(_redbName);
    }

    /// <summary>
    /// E2 — wraps an admin/SCIM mutation route in <c>Idempotency-Key</c> response caching.
    /// Inserts a PRE processor (cache lookup → short-circuit on hit) immediately after the
    /// transaction-scope opener returned by <see cref="WithRedbTx"/>, runs the supplied
    /// <paramref name="business"/> processor, then appends a POST processor that captures
    /// the response into the cache. Idempotency is a no-op when the named-redb factory is
    /// not configured (tests / dev) or when <see cref="IdempotencyOptions.Enabled"/> is
    /// <c>false</c> — in either case the route degrades to plain <see cref="WithRedbTx"/>.
    /// </summary>
    /// <summary>
    /// RFC 6749 §2.3 client identifier extractor for per-client throttle buckets on
    /// <c>/connect/token</c> and <c>/connect/par</c>. OAuth clients deliver
    /// <c>client_id</c> via one of two channels:
    /// <list type="number">
    ///   <item>HTTP Basic Auth header — confidential clients (RFC 6749 §2.3.1);</item>
    ///   <item>Form-encoded body parameter — public clients (RFC 6749 §3.2.1).</item>
    /// </list>
    /// The original extractor read only HTTP headers, which always returned <c>null</c> for
    /// either channel (the header name is <c>Authorization</c>, not <c>client_id</c>; and
    /// form params are body, not headers). Every token request therefore fell back to the
    /// literal string <c>"anonymous"</c> — collapsing the per-client throttle into a single
    /// shared bucket. Visible in <c>demo_throttle_rfc6585</c> ("KeyedThrottle isolation
    /// broken") and as collateral 429s in <c>demo_jwks_rotation</c> once unrelated demos ran
    /// faster than the throttle window could reset.
    /// </summary>
    private static string ExtractClientIdForThrottle(IExchange e)
    {
        // (1) HTTP Basic Auth — RFC 6749 §2.3.1. Decode "Basic base64(client_id:client_secret)".
        if (e.In.Headers.TryGetValue("Authorization", out var authObj) && authObj is string auth
            && auth.Length > 6
            && auth.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var decoded = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(auth.AsSpan(6).ToString()));
                var colon = decoded.IndexOf(':');
                var clientId = colon > 0 ? decoded[..colon] : decoded;
                if (!string.IsNullOrEmpty(clientId)) return clientId;
            }
            catch
            {
                // Malformed Basic — fall through to body lookup.
            }
        }

        // (2) Form-encoded body — RFC 6749 §3.2.1. The HTTP transport parses
        // application/x-www-form-urlencoded into IDictionary<string, object?>.
        if (e.In.Body is IDictionary<string, object?> body
            && body.TryGetValue("client_id", out var cid)
            && cid?.ToString() is { Length: > 0 } cidStr)
            return cidStr;

        return "anonymous";
    }

    private IRouteDefinition WithIdempotentTx(IRouteDefinition route, string scope, IProcessor business, bool wrapInRedbTx = true)
    {
        // wrapInRedbTx=false: routes whose business processor primarily writes through a
        // DI-scoped store / OpenIddict manager (which opens its OWN IRedbService and hence
        // its own SqliteRedbConnection) — wrapping in route-level redb-tx holds the writer
        // lock on the per-exchange connection while the store's separate connection races
        // for the same SQLite file, causing self-deadlock + busy_timeout cascades (~34s
        // observed). Idempotency pre/post still apply (their cache hits/writes go through
        // the per-exchange redb), they just no longer share a transaction with the body.
        var withTx = wrapInRedbTx ? WithRedbTx(route) : route;
        var pre = BuildIdempotencyPre(scope);
        if (pre is not null) withTx = withTx.Process(pre);
        withTx = withTx.Process(business);
        var post = BuildIdempotencyPost();
        if (post is not null) withTx = withTx.Process(post);
        return withTx;
    }

    /// <summary>
    /// E2 helper: builds the PRE idempotency processor for routes whose chain includes
    /// extra steps (Throttle, RequireSelfOrAdmin, etc.) that prevent using
    /// <see cref="WithIdempotentTx"/>. Returns <c>null</c> when idempotency is disabled or
    /// the named-redb factory is missing — callers conditionally append the result.
    /// </summary>
    private IProcessor? BuildIdempotencyPre(string scope)
    {
        if (!_options.Idempotency.Enabled) return null;
        var loggerFactory = _sp.GetService<ILoggerFactory>();
        return new IdempotencyProcessor(
            Context!, _redbName, scope, _options.Idempotency,
            _sp.GetService<TimeProvider>() ?? TimeProvider.System,
            loggerFactory?.CreateLogger<IdempotencyProcessor>());
    }

    /// <summary>E2 paired POST processor; see <see cref="BuildIdempotencyPre"/>.</summary>
    private IProcessor? BuildIdempotencyPost()
    {
        if (!_options.Idempotency.Enabled) return null;
        var loggerFactory = _sp.GetService<ILoggerFactory>();
        return new IdempotencyCaptureProcessor(
            Context!, _redbName, _options.Idempotency,
            _sp.GetService<TimeProvider>() ?? TimeProvider.System,
            loggerFactory?.CreateLogger<IdempotencyCaptureProcessor>());
    }

    private static void MapOAuthExceptionToRfc6749Response(IExchange exchange)
    {
        var ex = exchange.Exception;
        var error = ex?.Data["error"]?.ToString() ?? "server_error";
        var description = ex?.Data["error_description"]?.ToString() ?? ex?.Message ?? "An error occurred.";

        var outMsg = EnsureOut(exchange);
        outMsg.Body = ErrorResponse(error, description);
        outMsg.Headers["redbHttp.ResponseCode"] = 400;
    }

    /// <summary>
    /// Ensures <see cref="IExchange.Out"/> exists as a separate message. Never alias
    /// <c>Out</c> to <c>In</c>: writing the response into the request message corrupts
    /// the original body for anything that re-reads it later in the pipeline.
    /// </summary>
    private static IMessage EnsureOut(IExchange exchange)
    {
        if (exchange.Out is null)
        {
            exchange.Pattern = ExchangePattern.InOut;
            exchange.Out = exchange.In.Clone();
            exchange.Out.Body = null;
            exchange.Out.Headers.Clear();
        }
        return exchange.Out;
    }

    private static object ErrorResponse(string error, string description) =>
        new Dictionary<string, object?>
        {
            ["error"] = error,
            ["error_description"] = description
        };

    private static bool IsOAuthError(Exception? ex)
        => ex?.Data.Contains("error") == true;
}
