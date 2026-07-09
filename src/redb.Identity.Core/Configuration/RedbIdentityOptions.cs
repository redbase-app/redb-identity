using Microsoft.IdentityModel.Tokens;
using redb.Identity.Contracts.Configuration;

namespace redb.Identity.Core.Configuration;

/// <summary>
/// Configuration options for redb.Identity.
/// </summary>
public class RedbIdentityOptions
{
    /// <summary>
    /// Named redb instance to use. When null or empty, resolves default <c>IRedbService</c>.
    /// </summary>
    public string? RedbInstanceName { get; set; }

    /// <summary>
    /// Cross-module shared options (Issuer + Features). Single source of truth
    /// for both Core (DI registration, OpenIddict configuration, direct-vm
    /// route registration) and Http (discovery URL formatting, cookie Secure
    /// detection, HTTP endpoint mounting). Bound from the <c>Identity:*</c>
    /// section of <c>context.json</c>. The convenience properties
    /// <see cref="Issuer"/> and <see cref="Features"/> are proxies onto this
    /// instance so existing call-sites keep working unchanged.
    /// </summary>
    public IdentitySharedOptions Shared { get; set; } = new();

    /// <summary>
    /// Cross-module feature toggles. Proxy onto <see cref="Shared"/>.<see cref="IdentitySharedOptions.Features"/>.
    /// </summary>
    public IdentityFeatureFlags Features
    {
        get => Shared.Features;
        set => Shared.Features = value;
    }

    /// <summary>
    /// Token endpoint throttle: max requests per period per client.
    /// Default: 10.
    /// </summary>
    public int TokenThrottleMaxPerPeriod { get; set; } = 10;

    /// <summary>
    /// Token endpoint throttle period.
    /// Default: 1 second.
    /// </summary>
    public TimeSpan TokenThrottlePeriod { get; set; } = TimeSpan.FromSeconds(1);

    /// <summary>
    /// Retention period (days) for expired/revoked tokens before cleanup deletes them.
    /// Default: 30.
    /// </summary>
    public int TokenRetentionDays { get; set; } = 30;

    /// <summary>
    /// Interval between automatic token cleanup runs.
    /// Set to <see cref="TimeSpan.Zero"/> or <c>Timeout.InfiniteTimeSpan</c> to disable automatic cleanup.
    /// Default: 1 hour.
    /// </summary>
    public TimeSpan TokenCleanupInterval { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Batch size for soft-delete purge operations in <see cref="Services.BackgroundDeletionService"/>.
    /// Default: 50.
    /// </summary>
    public int TokenCleanupBatchSize { get; set; } = 50;

    /// <summary>
    /// Retention period (days) for revoked sessions before cleanup deletes them.
    /// Default: 14.
    /// </summary>
    public int SessionRetentionDays { get; set; } = 14;

    /// <summary>
    /// S-track: idle timeout. A session whose <c>LastAccessedAt</c> is older
    /// than this is auto-revoked on the next <c>SessionService.ListAsync</c> /
    /// <c>SessionCleanupProcessor</c> pass. Mirrors industry defaults
    /// (Keycloak 30 min, Okta 2 h, Auth0 3 days). Default: 24 h — middle of
    /// the range, lets active dev / cli sessions stay alive overnight while
    /// killing forgotten ones within a day.
    /// </summary>
    public TimeSpan SessionIdleTimeout { get; set; } = TimeSpan.FromHours(24);

    /// <summary>
    /// S-track: absolute timeout regardless of activity. A session whose
    /// <c>DateCreate</c> is older than this is auto-revoked even if it was
    /// just refreshed. Cap on total lifetime so a long-lived refresh-token
    /// chain doesn't keep one cookie alive forever. Default: 30 days.
    /// </summary>
    public TimeSpan SessionAbsoluteTimeout { get; set; } = TimeSpan.FromDays(30);

    /// <summary>
    /// Interval between automatic session cleanup runs.
    /// Set to <see cref="TimeSpan.Zero"/> or <c>Timeout.InfiniteTimeSpan</c> to disable.
    /// Default: 1 hour.
    /// </summary>
    public TimeSpan SessionCleanupInterval { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// B3: interval between automatic cleanup runs for expired server-side MFA OTP rows
    /// (<see cref="Models.MfaOtpProps"/>). Set to <see cref="TimeSpan.Zero"/> or
    /// <c>Timeout.InfiniteTimeSpan</c> to disable. Default: 1 hour. Clustered — runs on
    /// the route-leader node only.
    /// </summary>
    public TimeSpan MfaOtpCleanupInterval { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// W6-0: maximum lifetime of an entry in the backchannel revoked-sids list. Server clamps
    /// any client-supplied <c>ExpiresAt</c> to <c>now + RevokedSidsMaxRetention</c>. Should be
    /// at least the longest cookie / refresh-token lifetime among Relying Parties.
    /// Default: 24 hours.
    /// </summary>
    public TimeSpan RevokedSidsMaxRetention { get; set; } = TimeSpan.FromHours(24);

    /// <summary>
    /// W6-0: interval between cleanup runs that purge expired entries from the
    /// <c>identity.revoked_sid</c> PROPS table. Set to <see cref="TimeSpan.Zero"/> or
    /// <c>Timeout.InfiniteTimeSpan</c> to disable. Clustered — runs on the route-leader
    /// node only. Default: 1 hour.
    /// </summary>
    public TimeSpan RevokedSidsCleanupInterval { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Interval at which each replica reloads the DataProtection XML key-ring snapshot
    /// (<see cref="DataProtection.RedbXmlRepository"/>) from PROPS storage. Runs per-node
    /// (NOT cluster-leader-only) so every replica picks up keys rotated by other nodes,
    /// preventing split-key-ring windows after rotation.
    /// Set to <see cref="TimeSpan.Zero"/> or <see cref="Timeout.InfiniteTimeSpan"/> to disable
    /// — safe for single-instance deployments where initial snapshot at
    /// <c>RedbXmlRepositoryInitListener.OnContextStarting</c> is sufficient.
    /// Default: 12 hours (≤ half of <c>KeyManagementOptions.AutoRefreshIntervalForActiveKey</c> 24h, per Nyquist).
    /// </summary>
    public TimeSpan XmlRepositoryRefreshInterval { get; set; } = TimeSpan.FromHours(12);

    /// <summary>
    /// MFA-3: WebAuthn (FIDO2 / Passkey) configuration. Disabled by default; set
    /// <see cref="IdentityWebAuthnOptions.Enabled"/> to <c>true</c> and configure
    /// <see cref="IdentityWebAuthnOptions.RpId"/> + <see cref="IdentityWebAuthnOptions.Origins"/>
    /// to expose <c>/connect/mfa/webauthn/*</c> routes and the per-credential CRUD endpoints.
    /// </summary>
    public IdentityWebAuthnOptions WebAuthn { get; set; } = new();

    /// <summary>
    /// Issuer URI for the identity server (appears in <c>iss</c> claim and discovery document).
    /// Required for production; defaults to <c>https://localhost/</c> for development.
    /// Proxy onto <see cref="Shared"/>.<see cref="IdentitySharedOptions.Issuer"/>.
    /// </summary>
    public Uri Issuer
    {
        get => Shared.Issuer;
        set => Shared.Issuer = value;
    }

    /// <summary>
    /// Signing credentials for JWT tokens. When empty, ephemeral keys are used (dev only).
    /// </summary>
    public List<SigningCredentials> SigningCredentials { get; set; } = [];

    /// <summary>
    /// Encryption credentials for token payloads. When empty, ephemeral keys are used (dev only).
    /// </summary>
    public List<EncryptingCredentials> EncryptionCredentials { get; set; } = [];

    /// <summary>
    /// When <c>true</c>, allows <c>AddRedbIdentityServer</c> to fall back to ephemeral signing /
    /// encryption keys if no <see cref="SigningCredentials"/> / <see cref="EncryptionCredentials"/>
    /// were configured. <b>Must remain <c>false</c> in production</b> — ephemeral keys split the
    /// JWKS across cluster replicas (tokens issued by one node fail validation on another) and
    /// invalidate every live token on restart. Set to <c>true</c> only in Development /
    /// integration-test fixtures. Default: <c>false</c>.
    /// </summary>
    public bool AllowEphemeralKeys { get; set; } = false;

    /// <summary>
    /// A3: when <c>true</c>, OpenIddict signing / encryption credentials are populated from
    /// the PROPS-backed <see cref="Keys.ISigningKeyStore"/>. Initial keys are generated on
    /// first context start (<see cref="Module.SigningKeyInitListener"/>) if the store is
    /// empty; private PEM material is encrypted with the DataProtection key ring. Cluster
    /// replicas share one JWKS because they read from the same PROPS rows.
    /// <para>
    /// Mutually exclusive with pre-populated <see cref="SigningCredentials"/> /
    /// <see cref="EncryptionCredentials"/>: when both are configured, store-provided
    /// credentials are APPENDED after the configured ones so operators retain the option of
    /// an HSM/KMS-backed primary with an PROPS secondary for disaster recovery.
    /// </para>
    /// Default: <c>false</c> (feature is opt-in until rotation automation ships).
    /// </summary>
    public bool UsePropsSigningKeyStore { get; set; } = false;

    /// <summary>Access token lifetime. Default: 1 hour.</summary>
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>Refresh token lifetime. Default: 14 days.</summary>
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(14);

    /// <summary>
    /// Refresh token reuse leeway. After rotation, the old token remains valid for this window.
    /// <c>TimeSpan.Zero</c> = strict rotation (old token rejected immediately).
    /// Default: <c>TimeSpan.Zero</c> (strict).
    /// </summary>
    public TimeSpan RefreshTokenReuseLeeway { get; set; } = TimeSpan.Zero;

    /// <summary>Authorization code lifetime. Default: 5 minutes.</summary>
    public TimeSpan AuthorizationCodeLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Identity token lifetime. Default: 5 minutes.</summary>
    public TimeSpan IdentityTokenLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Disable access token encryption (tokens are signed but not encrypted). Default: false.</summary>
    public bool DisableAccessTokenEncryption { get; set; }

    /// <summary>
    /// Required OAuth scope for management API access.
    /// Clients must request this scope to call <c>/api/v1/identity/*</c> endpoints.
    /// Default: <c>identity:manage</c>.
    /// </summary>
    public string ManagementScope { get; set; } = "identity:manage";

    /// <summary>
    /// OAuth scope granting <b>self-service</b> access to the management API (B8).
    /// A token bearing this scope may invoke management endpoints only when the body / route
    /// <c>userId</c> matches the token's <c>sub</c> claim. Tokens bearing
    /// <see cref="ManagementScope"/> are treated as administrators and may target any user.
    /// Modeled on Keycloak's <c>manage-account</c> (self) vs <c>realm-admin</c> (cross-user)
    /// split. Default: <c>identity:account</c>.
    /// </summary>
    public string AccountScope { get; set; } = "identity:account";

    /// <summary>
    /// Group-membership gate for selected OAuth scopes. Maps
    /// <c>scopeName → groupName</c>. When a user-bound token request
    /// (authorization_code, password, device_code, or a refresh_token derived from
    /// these) requests one of the listed scopes, the OpenIddict pipeline rejects the
    /// request with <c>error=access_denied</c> unless the authenticated user is a
    /// (non-expired) member of the required group.
    /// <para>
    /// The <c>client_credentials</c> grant is intentionally unaffected — it has no
    /// user identity, so the existing <c>scp:{scope}</c> permission on the
    /// application is the authoritative gate for that flow.
    /// </para>
    /// <para>
    /// Typical bootstrap configuration:
    /// <c>{ ["identity:manage"] = "identity-admins" }</c> — restricts the
    /// management scope to members of the admin group.
    /// </para>
    /// Default: empty (no scope restrictions).
    /// </summary>
    public Dictionary<string, string> ScopeRequiredGroups { get; set; }
        = new(StringComparer.Ordinal);

    // ── Dynamic Client Registration (RFC 7591) ──
    // Note: the on/off toggle moved to <see cref="Features"/>.EnableDynamicRegistration.

    /// <summary>
    /// Grant types allowed for dynamically registered clients.
    /// Default: <c>["authorization_code", "refresh_token"]</c>.
    /// </summary>
    public string[] DynamicRegistrationAllowedGrantTypes { get; set; } =
        ["authorization_code", "refresh_token"];

    /// <summary>
    /// Scopes allowed for dynamically registered clients.
    /// Default: <c>["openid", "profile", "email", "phone", "address", "offline_access", "groups", "roles"]</c>.
    /// All of these are user-info scopes (claims about the user) and standard OIDC profile/contact
    /// scopes — none grant API privilege. Admin scopes (<c>identity:*</c>) and SCIM are intentionally
    /// excluded so anonymous DCR cannot self-elevate. Override the list to restrict further if needed.
    /// </summary>
    public string[] DynamicRegistrationAllowedScopes { get; set; } =
        ["openid", "profile", "email", "phone", "address", "offline_access", "groups", "roles"];

    /// <summary>
    /// Optional initial access token (RFC 7591 §1.2). When set, the <c>POST /connect/register</c>
    /// request must include <c>Authorization: Bearer {token}</c>. When null, the endpoint is open
    /// (rate-limited only).
    /// </summary>
    public string? DynamicRegistrationInitialAccessToken { get; set; }

    /// <summary>
    /// Per-IP throttle for the Dynamic Client Registration endpoint: max requests per
    /// <see cref="DynamicRegistrationThrottlePeriod"/>. Tunable independently from
    /// <see cref="TokenThrottleMaxPerPeriod"/> because DCR is a write-heavy admin
    /// endpoint with very different traffic shape than the token endpoint.
    /// Default: <c>5</c>.
    /// </summary>
    public int DynamicRegistrationThrottleMaxPerPeriod { get; set; } = 5;

    /// <summary>
    /// Window for <see cref="DynamicRegistrationThrottleMaxPerPeriod"/>. Default: 10 seconds.
    /// </summary>
    public TimeSpan DynamicRegistrationThrottlePeriod { get; set; } = TimeSpan.FromSeconds(10);

    // ── Device Code Flow (RFC 8628) ──
    // Note: the on/off toggle moved to <see cref="Features"/>.EnableDeviceCodeFlow.

    // ── Pushed Authorization Requests (RFC 9126 / Z6) ──
    // Note: the on/off toggle moved to <see cref="Features"/>.EnablePushedAuthorization.

    /// <summary>
    /// Z6 (RFC 9126 §2.1): when <c>true</c>, the authorization endpoint REJECTS requests
    /// that did not originate as a PAR (i.e. requests not carrying a <c>request_uri</c> issued
    /// by this server). Effective only when <see cref="IdentityFeatureFlags.EnablePushedAuthorization"/>
    /// is also <c>true</c>. Default: false.
    /// </summary>
    public bool RequirePushedAuthorizationRequests { get; set; }

    /// <summary>
    /// Z6: lifetime of a <c>request_uri</c> issued by the PAR endpoint. RFC 9126 §2.2 mandates
    /// it MUST be SHORT-LIVED; the typical value is 60 seconds. Default: 90 seconds.
    /// </summary>
    public TimeSpan PushedAuthorizationRequestLifetime { get; set; } = TimeSpan.FromSeconds(90);

    /// <summary>
    /// Z4 (RFC 9449): DPoP support — proof-of-possession-bound access tokens.
    /// See <see cref="DpopOptions"/> for full configuration.
    /// </summary>
    public DpopOptions Dpop { get; set; } = new();

    /// <summary>
    /// Lifetime of the device_code / user_code pair.
    /// Default: 10 minutes (RFC 8628 §3.2 recommends ≤ 15 min).
    /// </summary>
    public TimeSpan DeviceCodeLifetime { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Polling interval in seconds returned to the client in the device authorization response.
    /// Default: 5 seconds (per RFC 8628 §3.2).
    /// </summary>
    public int DeviceCodePollingInterval { get; set; } = 5;

    // ── Resource Owner Password Credentials (RFC 6749 §4.3) ──

    /// <summary>
    /// Enable the ROPC grant (<c>grant_type=password</c>). Opt-in only.
    /// Allows direct username/password to token exchange via <c>POST /connect/token</c>.
    /// Default: false.
    /// </summary>
    public bool EnablePasswordFlow { get; set; }

    // ── Token Exchange (RFC 8693) ──

    /// <summary>
    /// Enable the Token Exchange grant (<c>grant_type=urn:ietf:params:oauth:grant-type:token-exchange</c>).
    /// Allows delegation and impersonation token flows (RFC 8693).
    /// Default: false.
    /// </summary>
    public bool EnableTokenExchange { get; set; }

    /// <summary>
    /// Allow impersonation token exchange (the actor disappears — the new token looks like
    /// it was issued directly to the subject). When false, only delegation is allowed
    /// (the <c>act</c> claim preserves the actor chain).
    /// Default: false.
    /// </summary>
    public bool TokenExchangeAllowImpersonation { get; set; }

    /// <summary>
    /// Maximum depth of the <c>act</c> claim delegation chain.
    /// Prevents runaway chained exchanges. 0 = unlimited.
    /// Default: 5.
    /// </summary>
    public int TokenExchangeMaxDelegationDepth { get; set; } = 5;

    // ── Session / Login ──

    /// <summary>
    /// Path to the login page. Used for redirect when <c>login_required</c> on authorize.
    /// Default: <c>/login</c>.
    /// </summary>
    public string LoginPath { get; set; } = "/login";

    /// <summary>
    /// Path to the consent page. Used for redirect when <c>consent_required</c> on authorize.
    /// Default: <c>/consent</c>.
    /// </summary>
    public string ConsentPath { get; set; } = "/consent";

    /// <summary>
    /// Path to the MFA verification page. Used for redirect when MFA is required after login.
    /// Default: <c>/mfa</c>.
    /// </summary>
    public string MfaPath { get; set; } = "/mfa";

    /// <summary>
    /// Path to the MFA recovery code page.
    /// Default: <c>/mfa/recovery</c>.
    /// </summary>
    public string MfaRecoveryPath { get; set; } = "/mfa/recovery";

    /// <summary>
    /// Minimum delay between consecutive OTP send requests (SMS/Email).
    /// Prevents spamming an end user / running up SMS bills. Default: 60 seconds.
    /// </summary>
    public TimeSpan OtpCooldown { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Maximum OTP sends per user per rolling hour (SMS/Email combined).
    /// Default: 5.
    /// </summary>
    public int OtpMaxPerHour { get; set; } = 5;

    /// <summary>
    /// Tolerance (clock skew) applied to MFA lockout-window comparisons (B9 / BUG-5).
    /// A user is treated as locked out while <c>now &lt; LockedUntil + skew</c> and unlocked
    /// once <c>now &gt;= LockedUntil + skew</c>. Prevents premature unlock when the server
    /// clock is slightly fast relative to the clock that wrote <c>LockedUntil</c>.
    /// Default: 5 seconds.
    /// </summary>
    public TimeSpan MfaLockoutClockSkew { get; set; } = TimeSpan.FromSeconds(5);

    // ── MFA recovery codes (B4: PBKDF2 + per-user salt + pepper) ──

    /// <summary>
    /// Server-wide pepper applied to recovery-code hashing in addition to the per-user salt
    /// (base64-encoded, 16+ bytes recommended). When <c>null</c>:
    /// <list type="bullet">
    /// <item><description>If <see cref="AllowEphemeralKeys"/> is <c>true</c>, an ephemeral random
    /// pepper is generated at startup. Recovery codes are then unverifiable across restarts /
    /// across replicas.</description></item>
    /// <item><description>If <see cref="AllowEphemeralKeys"/> is <c>false</c>, registration of
    /// the identity server fails with an explanatory exception.</description></item>
    /// </list>
    /// Production deployments must configure a stable pepper distributed via a secret store.
    /// </summary>
    public string? RecoveryCodePepper { get; set; }

    /// <summary>
    /// PBKDF2-HMAC-SHA256 work factor (iterations) used when hashing newly generated recovery
    /// codes. OWASP guidance (2024) recommends ≥ 600 000 for SHA-256. Existing stored hashes
    /// continue to verify against the iteration count embedded in their format string.
    /// Default: 600 000.
    /// </summary>
    public int RecoveryCodePbkdf2Iterations { get; set; } = 600_000;

    /// <summary>
    /// Lifetime of the session cookie. After this the user must log in again.
    /// Default: 8 hours.
    /// </summary>
    public TimeSpan SessionCookieLifetime { get; set; } = TimeSpan.FromHours(8);

    // ── UI Customization ──

    /// <summary>
    /// Title shown on the login page. Default: <c>Sign In</c>.
    /// </summary>
    public string LoginTitle { get; set; } = "Sign In";

    /// <summary>
    /// URL of a logo image shown above the login form. When null, no logo is rendered.
    /// </summary>
    public string? LogoUrl { get; set; }

    /// <summary>
    /// Primary color for buttons and accents (CSS color value). Default: <c>#2563eb</c>.
    /// </summary>
    public string PrimaryColor { get; set; } = "#2563eb";

    /// <summary>
    /// Primary color hover state. Default: <c>#1d4ed8</c>.
    /// </summary>
    public string PrimaryColorHover { get; set; } = "#1d4ed8";

    /// <summary>
    /// Extra CSS injected into every identity page (login, consent, logout).
    /// </summary>
    public string? CustomCss { get; set; }

    // ── SCIM 2.0 (RFC 7643/7644) ──
    // Note: the on/off toggles moved to <see cref="Features"/>.EnableScim / EnableScimBulk.

    /// <summary>
    /// Required OAuth scope for SCIM API access.
    /// Clients must request this scope to call <c>/scim/v2/*</c> endpoints.
    /// Default: <c>scim</c>.
    /// </summary>
    public string ScimScope { get; set; } = "scim";

    /// <summary>
    /// H1: maximum number of operations accepted in one SCIM Bulk request. Mirrors the
    /// <c>bulk.maxOperations</c> field advertised in <c>/scim/v2/ServiceProviderConfig</c>.
    /// Default: 1000.
    /// </summary>
    public int ScimBulkMaxOperations { get; set; } = 1000;

    /// <summary>
    /// H1: maximum payload size (bytes) accepted in one SCIM Bulk request. Mirrors the
    /// <c>bulk.maxPayloadSize</c> field advertised in <c>/scim/v2/ServiceProviderConfig</c>.
    /// Default: 1 MiB.
    /// </summary>
    public int ScimBulkMaxPayloadSize { get; set; } = 1_048_576;

    // ── Federation (OIDC / external IdP) ──
    // Note: the on/off toggle moved to <see cref="Features"/>.EnableFederation.

    /// <summary>Configured external OIDC federation providers.</summary>
    public List<FederationProviderConfig> FederationProviders { get; set; } = [];

    // ── C2: Trusted reverse-proxy whitelist for client-IP resolution ──

    /// <summary>
    /// Whitelist of trusted reverse-proxy IPs / networks consulted by
    /// <see cref="Routes.Processors.TrustedProxyResolverProcessor"/> when sanitizing the
    /// <c>redbHttp.RemoteAddress</c> exchange header before per-IP throttling (C1) sees it.
    /// <para>
    /// Secure-by-default: <see cref="ReverseProxyOptions.TrustForwardedFor"/> is <c>false</c>,
    /// so <c>X-Forwarded-For</c> / <c>Forwarded</c> headers are ignored entirely and the socket
    /// IP is always used. To enable forwarded-IP resolution behind a reverse proxy, set
    /// <c>TrustForwardedFor=true</c> AND populate <see cref="ReverseProxyOptions.KnownProxies"/>
    /// or <see cref="ReverseProxyOptions.KnownNetworks"/> with the proxy address(es).
    /// </para>
    /// </summary>
    public ReverseProxyOptions ReverseProxies { get; set; } = new();

    // ── C1: Per-IP / per-(IP+username) rate limiting ──

    /// <summary>
    /// Configuration for the C1 rate-limit guard sitting in front of <c>/connect/token</c>,
    /// <c>/login</c> and the MFA endpoints. See <see cref="RateLimitOptions"/> for trust model
    /// and backend selection. Disabled by default; enable + select a backend to activate.
    /// </summary>
    public RateLimitOptions RateLimit { get; set; } = new();

    /// <summary>
    /// Length / size limits applied by management & registration processors when validating
    /// inbound payloads. Defaults match historical hardcoded values; tune per deployment.
    /// </summary>
    public IdentityValidationOptions Validation { get; set; } = new();

    /// <summary>
    /// Hardening knobs for the OIDC federation state parameter (anti-replay, browser-binding, TTL).
    /// </summary>
    public FederationStateOptions FederationState { get; set; } = new();

    /// <summary>
    /// N-4 (Session C): outbound SMTP transport used by the transactional e-mail channel
    /// (password recovery, MFA delivery, account notices). Disabled by default — a host
    /// that does not enable SMTP must register an alternative <c>IEmailNotificationChannel</c>
    /// (e.g. the in-memory channel used by integration tests, or a SendGrid adapter).
    /// </summary>
    public SmtpOptions Smtp { get; set; } = new();

    /// <summary>
    /// N-4 (Session C): tunables for the anonymous password-recovery flow (TTL etc.).
    /// </summary>
    public PasswordRecoveryOptions PasswordRecovery { get; set; } = new();

    /// <summary>
    /// N-4 (Session C, sub-step N4-6): tunables + feature gate for the e-mail-verification
    /// flow. Disabled by default — opt-in until a host wires an
    /// <see cref="Services.IEmailNotificationChannel"/> and configures per-client
    /// <c>ApplicationProps.EmailVerifyUris</c>.
    /// </summary>
    public EmailVerificationOptions EmailVerification { get; set; } = new();

    /// <summary>
    /// N-4 (Session E, sub-step N4-7): tunables + feature gate for the strict
    /// verify-then-commit change-of-e-mail flow. Disabled by default — opt-in until a
    /// host wires an <see cref="Services.IEmailNotificationChannel"/> and configures
    /// per-client <c>ApplicationProps.ChangeEmailUris</c>. When this option is enabled
    /// hosts SHOULD also set <see cref="ChangeEmailOptions.RejectSoftEmailChange"/> to
    /// <c>true</c> so the soft <c>/me/profile</c> path stops accepting an unverified
    /// e-mail update and forces all e-mail changes through the strict flow.
    /// </summary>
    public ChangeEmailOptions ChangeEmail { get; set; } = new();

    /// <summary>
    /// N-3 (sub-step N3-7): feature gate + tunables for the anonymous self-service
    /// account-registration flow. Disabled by default — corporate identity deployments
    /// that provision users via admin / SCIM should leave this off.
    /// </summary>
    public RegistrationOptions Registration { get; set; } = new();

    /// <summary>
    /// C9 — cookie security defaults: <c>__Host-</c>/<c>__Secure-</c> name prefixes,
    /// <c>SameSite</c> mode, etc. All cookies emitted by Identity inherit
    /// <c>HttpOnly</c> and <c>Secure</c> (when issuer is https) automatically;
    /// these knobs cover the spec-defined extras.
    /// </summary>
    public IdentityCookieOptions Cookies { get; set; } = new();

    /// <summary>
    /// C10 — at-rest encryption for the ASP.NET DataProtection key-ring stored in redb PROPS.
    /// Without an encryptor configured, key-ring elements live in the database in plaintext;
    /// a database leak then compromises every Identity-issued cookie / federation state /
    /// MFA setup token.
    /// </summary>
    public DataProtectionOptions DataProtection { get; set; } = new();

    /// <summary>
    /// E2 — <c>Idempotency-Key</c> response cache for admin/SCIM mutations. See
    /// <see cref="IdempotencyOptions"/> for behaviour and storage details.
    /// </summary>
    public IdempotencyOptions Idempotency { get; set; } = new();

    /// <summary>
    /// C12 — password hashing algorithm + parameters for newly stored passwords, and
    /// auto-rehash of legacy formats on successful login. See
    /// <see cref="PasswordHashingOptions"/>.
    /// </summary>
    public PasswordHashingOptions PasswordHashing { get; set; } = new();

    /// <summary>
    /// H10 — server-side password policy: length, composition, history reuse,
    /// expiration, breach screening. Defaults are STRICT (NIST SP 800-63B / OWASP
    /// ASVS 4.0.3 §2.1) so a freshly bootstrapped deployment is secure-by-default;
    /// every knob is overridable via the standard 5-layer config pipeline.
    /// </summary>
    public PasswordPolicyOptions PasswordPolicy { get; set; } = new();

    /// <summary>
    /// B1 — emergency local-admin bootstrap endpoint (<c>POST /internal/bootstrap-admin</c>).
    /// On a brand-new deployment with an empty identity database (no users, groups, OIDC
    /// clients) there is no way to log in — even <c>client_credentials</c> requires a
    /// pre-registered confidential client. This endpoint atomically creates the first
    /// admin user, the <c>identity-admins</c> group, the <c>identity-web</c> OIDC client
    /// and a <c>SystemFlag(name=bootstrap_completed)</c> sentinel; subsequent calls
    /// return <c>410 Gone</c>. Disabled by default — set
    /// <see cref="BootstrapOptions.Enabled"/> + <see cref="BootstrapOptions.Secret"/>
    /// (env-only!) to enable.
    /// </summary>
    public BootstrapOptions Bootstrap { get; set; } = new();

    /// <summary>
    /// Default-credential seeder for the well-known <c>admin</c> user that ships
    /// in the base redb SQL seed (<c>_users.id = 1</c>, <c>login = "admin"</c>,
    /// empty password). On host startup, <c>SeedAdminPasswordHostedService</c>
    /// looks up the user by <see cref="SeedAdminOptions.Login"/>; if found and its
    /// stored password is empty, it is hashed via the configured
    /// <see cref="redb.Core.Security.IPasswordHasher"/> and persisted, so a fresh
    /// install supports <c>admin/admin</c> sign-in out-of-the-box. Logs a loud
    /// startup WARNING when the password is the default <c>admin</c>.
    /// </summary>
    public SeedAdminOptions SeedAdmin { get; set; } = new();

    /// <summary>
    /// Default OIDC-client seeder that ensures the canonical Web Console client
    /// (<see cref="SeedWebClientOptions.ClientId"/>) exists in the OpenIddict
    /// application store on host startup. Sister to <see cref="SeedAdmin"/> —
    /// fully idempotent (no-op when the client already exists), opinionated
    /// defaults wired for the bundled <c>redb.Identity.Web</c> BFF running on
    /// <c>https://localhost:7000</c>. For non-default deployments override
    /// <see cref="SeedWebClientOptions.RedirectUris"/> and
    /// <see cref="SeedWebClientOptions.PostLogoutRedirectUris"/> via
    /// <c>context.json</c> / env-vars.
    /// </summary>
    public SeedWebClientOptions SeedWebClient { get; set; } = new();

    /// <summary>
    /// W6-0 — default seeder for the <c>client_credentials</c> service-account
    /// used by a polling Web BFF to push/poll the backchannel revoked-sids list.
    /// Sister to <see cref="SeedWebClient"/>; disabled by default so it does not
    /// inflate the OpenIddict client store on hosts that don't run the Web BFF.
    /// </summary>
    public SeedBackchannelClientOptions SeedBackchannelClient { get; set; } = new();
}

/// <summary>
/// Options for the default-admin password seeder that ensures the well-known
/// <c>admin</c> user from the base redb SQL seed has a usable password on a fresh
/// install. Idempotent: only updates when the stored password is empty.
/// </summary>
public sealed class SeedAdminOptions
{
    /// <summary>Default plaintext password used when no override is supplied.</summary>
    public const string DefaultPassword = "admin";

    /// <summary>Master switch; default <c>true</c>. Set to <c>false</c> to disable seeding entirely.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Login of the seed admin user; default <c>admin</c>.</summary>
    public string Login { get; set; } = "admin";

    /// <summary>
    /// Plain-text password to hash and store when the user has no password. Default
    /// <c>admin</c>. <b>Convenience for fresh deployments only</b> — change this
    /// (or rotate the password via the management API) before exposing the host to
    /// untrusted networks. Leaving the default produces a startup WARNING.
    /// </summary>
    public string Password { get; set; } = DefaultPassword;
}

/// <summary>
/// Options for the default OIDC-client seeder that ensures the canonical
/// <c>identity-web</c> client exists in the OpenIddict application store on a
/// fresh install. Idempotent: skips when a client with the same
/// <see cref="ClientId"/> already exists. Defaults are wired for the bundled
/// <c>redb.Identity.Web</c> BFF.
/// </summary>
public sealed class SeedWebClientOptions
{
    /// <summary>Master switch; default <c>true</c>. Set to <c>false</c> to disable seeding entirely.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>OIDC client identifier; default <c>identity-web</c> (matches Web BFF appsettings).</summary>
    public string ClientId { get; set; } = "identity-web";

    /// <summary>
    /// Optional client secret. When empty the client is registered as a Public
    /// client (PKCE-only). The bundled <c>redb.Identity.Web</c> BFF runs as a
    /// public client by default — leave this empty unless you flip Web to
    /// confidential mode.
    /// </summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>Display name shown on the consent page; default "Identity Web Console".</summary>
    public string DisplayName { get; set; } = "Identity Web Console";

    /// <summary>
    /// Allowed redirect URIs (post-authorization callback). Default points at
    /// <c>https://localhost:7000/signin-oidc</c> (Web BFF dev binding).
    /// </summary>
    public List<string> RedirectUris { get; set; } = new()
    {
        "https://localhost:7000/signin-oidc",
    };

    /// <summary>
    /// Allowed post-logout redirect URIs. Default points at
    /// <c>https://localhost:7000/signout-callback-oidc</c>.
    /// </summary>
    public List<string> PostLogoutRedirectUris { get; set; } = new()
    {
        "https://localhost:7000/signout-callback-oidc",
    };

    /// <summary>
    /// Allowed scopes the client may request. Default mirrors the Web BFF
    /// requested scopes (openid, profile, email, roles, offline_access,
    /// identity:manage, identity:account). Standard OIDC scopes are always permitted
    /// regardless of this list — entries here additionally grant non-standard scopes via
    /// <c>Permissions.Prefixes.Scope</c>. <c>identity:account</c> is included so the
    /// BFF can call self-service <c>/me/*</c> endpoints (e.g. native consent grant)
    /// on behalf of the signed-in user without further deployment configuration.
    /// </summary>
    public List<string> Scopes { get; set; } = new()
    {
        "openid", "profile", "email", "roles", "offline_access", "identity:manage", "identity:account",
    };
}

/// <summary>
/// Options for the W6-0 backchannel service-account seeder. Ensures a confidential
/// <c>client_credentials</c> OpenIddict application exists so a polling Web BFF
/// can push and read revoked-sids without holding an end-user token. Idempotent:
/// skipped when an application with the same <see cref="ClientId"/> already exists.
/// </summary>
public sealed class SeedBackchannelClientOptions
{
    /// <summary>Master switch. Default <c>false</c> — opt-in per deployment.</summary>
    public bool Enabled { get; set; } = false;

    /// <summary>Client identifier of the service account. Default <c>identity-backchannel</c>.</summary>
    public string ClientId { get; set; } = "identity-backchannel";

    /// <summary>
    /// Client secret. Must be non-empty when <see cref="Enabled"/> is true — the
    /// seeder logs and skips when missing rather than registering a public client
    /// (client_credentials requires a confidential client per RFC 6749 §4.4).
    /// </summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>Display name shown in admin UI / logs.</summary>
    public string DisplayName { get; set; } = "Identity Backchannel Service Account";

    /// <summary>
    /// Scopes the service account is allowed to request. Default <c>identity:manage</c>
    /// — sufficient to call <c>/api/v1/identity/revoked-sids</c>.
    /// </summary>
    public List<string> Scopes { get; set; } = new() { "identity:manage" };
}

/// (<c>POST /internal/bootstrap-admin</c>). The secret MUST come from environment
/// (e.g. <c>IDENTITY__BOOTSTRAP__SECRET</c>) and never from <c>context.json</c>
/// (which is checked into source control).
/// </summary>
public sealed class BootstrapOptions
{
    /// <summary>
    /// Master switch. When <c>false</c> (default) the route is registered but
    /// always returns <c>404 Not Found</c> — operators can leave the option in
    /// <c>context.json</c> permanently disabled and only flip it via env-var on
    /// the very first deploy.
    /// </summary>
    public bool Enabled { get; set; } = false;

    /// <summary>
    /// Shared secret required in the <c>X-Bootstrap-Secret</c> header.
    /// Compared with <see cref="System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(System.ReadOnlySpan{byte}, System.ReadOnlySpan{byte})"/>
    /// so the comparison does not leak information through timing.
    /// Must be at least 32 characters when <see cref="Enabled"/> is true
    /// (validated at startup); env-only by convention.
    /// </summary>
    public string? Secret { get; set; }

    /// <summary>
    /// Name of the group that the freshly-created admin user joins. Should
    /// match <c>RedbIdentityOptions.ScopeRequiredGroups["identity:admin"]</c>
    /// so the new admin can immediately use the management scope. Default
    /// <c>identity-admins</c>.
    /// </summary>
    public string AdminGroupName { get; set; } = "identity-admins";

    /// <summary>
    /// OAuth scope that the bootstrap admin needs in order to call the
    /// management surface. Defaults to the conventional
    /// <c>identity:admin</c>. The processor creates the scope (if absent),
    /// the gating <see cref="RedbIdentityOptions.ScopeRequiredGroups"/> entry,
    /// and a <see cref="Models.ClaimMapperProps"/> mapping
    /// <c>group(<see cref="AdminGroupName"/>) → scope(<see cref="AdminScope"/>)</c>.
    /// </summary>
    public string AdminScope { get; set; } = "identity:admin";

    /// <summary>
    /// ClientId issued for the canonical first-party admin web application.
    /// Default <c>identity-web</c>.
    /// </summary>
    public string WebClientId { get; set; } = "identity-web";
}

/// <summary>
/// Server-side input-length limits used by Identity validation helpers.
/// All values default to the original hardcoded constants.
/// </summary>
public sealed class IdentityValidationOptions
{
    /// <summary>Max length for identifier-like fields (login, name, etc.). Default 128.</summary>
    public int MaxIdentifierLength { get; set; } = 128;

    /// <summary>Max length for free-form display names. Default 256.</summary>
    public int MaxDisplayNameLength { get; set; } = 256;

    /// <summary>Max length for free-form descriptions. Default 1024.</summary>
    public int MaxDescriptionLength { get; set; } = 1024;

    /// <summary>Minimum length for passwords / client secrets. Default 8.</summary>
    public int MinPasswordLength { get; set; } = 8;

    /// <summary>Maximum length for passwords / client secrets. Default 512.</summary>
    public int MaxPasswordLength { get; set; } = 512;

    /// <summary>
    /// Optional override for the identifier regex (logins, role names, etc.).
    /// Default (when null/empty): <c>^[a-zA-Z0-9\-_.]+$</c>.
    /// Invalid patterns silently fall back to the default.
    /// </summary>
    public string? IdentifierPattern { get; set; }

    /// <summary>
    /// Optional override for the email regex.
    /// Default (when null/empty): <c>^[^@\s]+@[^@\s]+\.[^@\s]+$</c>.
    /// </summary>
    public string? EmailPattern { get; set; }

    /// <summary>
    /// Optional override for the phone-number regex.
    /// Default (when null/empty): E.164 — <c>^\+[1-9]\d{1,14}$</c>.
    /// </summary>
    public string? PhonePattern { get; set; }
}

/// <summary>
/// C6 — hardening for the encrypted federation <c>state</c> blob and the
/// surrounding callback ceremony.
/// </summary>
public sealed class FederationStateOptions
{
    /// <summary>
    /// Maximum lifetime of an encrypted state blob from issuance to redeem.
    /// Default: 5 minutes (matches OIDC spec recommendation for short-lived
    /// authorization-request artefacts).
    /// </summary>
    public TimeSpan StateMaxAge { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// When <c>true</c> (default), every state blob carries a unique <c>jti</c>
    /// that is recorded in the nonce store on first use; subsequent presentations
    /// with the same <c>jti</c> are rejected (one-time-use, RFC 6749 §10.12-style).
    /// Disable only for testing.
    /// </summary>
    public bool RequireOneTimeUse { get; set; } = true;

    /// <summary>
    /// When <c>true</c>, the challenge processor mints a per-flow secret, hashes it
    /// into the state blob, and the HTTP layer pins the secret to the user-agent via
    /// a <c>Secure HttpOnly SameSite=Lax</c> cookie. The callback rejects the flow
    /// if the cookie is absent or its hash mismatches. Default: <c>false</c> —
    /// opt-in because non-HTTP callers (CLI / SPA without cookie jar) cannot satisfy
    /// the binding contract. See <see cref="BindingCookieName"/>.
    /// </summary>
    public bool RequireBrowserBinding { get; set; } = false;

    /// <summary>
    /// Name of the cookie that carries the per-flow browser-binding secret when
    /// <see cref="RequireBrowserBinding"/> is enabled. Default: <c>redb_fed_b</c>.
    /// </summary>
    public string BindingCookieName { get; set; } = "redb_fed_b";

    /// <summary>
    /// Backend for the one-time-use nonce store. <c>memory</c> (default) is single-node;
    /// <c>redis</c> is required for multi-instance Identity deployments to make the
    /// guarantee cluster-global. See <see cref="RedisConnectionString"/>.
    /// </summary>
    public string Backend { get; set; } = "memory";

    /// <summary>
    /// Redis connection string for the nonce store. When null/empty and
    /// <see cref="Backend"/> = <c>redis</c>, falls back to <see cref="RedbIdentityOptions.RateLimit"/>.<see cref="RateLimitOptions.RedisConnectionString"/>.
    /// </summary>
    public string? RedisConnectionString { get; set; }

    /// <summary>
    /// Key prefix used by the Redis nonce store. Default: <c>redb:identity:fed:nonce:</c>.
    /// </summary>
    public string RedisKeyPrefix { get; set; } = "redb:identity:fed:nonce:";
}


/// <summary>
/// SameSite cookie modes per RFC 6265bis. <c>None</c> requires <c>Secure</c>.

/// <summary>
/// C10 — DataProtection at-rest hardening.
/// <para>Three variants are supported (in priority order if multiple are set):</para>
/// <list type="number">
///   <item><b>Custom KMS</b> via <see cref="CustomEncryptorFactory"/> — caller supplies an
///   <c>IXmlEncryptor</c> wired to Vault / Azure Key Vault / AWS KMS / etc.</item>
///   <item><b>X.509 certificate</b> via <see cref="Certificate"/> — thumbprint lookup in
///   the local store, or PFX path on disk. Cross-platform; preferred for cluster.</item>
///   <item><b>AES-GCM master key</b> via <see cref="MasterKey"/> — 32-byte key in base64.
///   Smallest deployments / single-node dev.</item>
/// </list>
/// <para>If <see cref="RequireAtRestEncryption"/> is <c>true</c> AND
/// <see cref="RedbIdentityOptions.AllowEphemeralKeys"/> is <c>false</c> AND none of the above
/// is configured, <c>AddRedbIdentityServer</c> throws on startup.</para>
/// <para><b>Migration:</b> existing plaintext key-ring entries stay readable
/// (ASP.NET DataProtection handles mixed plain+encrypted entries natively).
/// New keys written after enabling encryption are encrypted; rotation eventually
/// retires the plaintext entries.</para>
/// </summary>
public sealed class DataProtectionOptions
{
    /// <summary>
    /// When <c>true</c> (default) and ephemeral keys are not allowed, startup fails
    /// unless one of <see cref="MasterKey"/>, <see cref="Certificate"/>, or
    /// <see cref="CustomEncryptorFactory"/> is configured.
    /// </summary>
    public bool RequireAtRestEncryption { get; set; } = true;

    /// <summary>
    /// 32-byte AES-256 key, base64-encoded. Used by the built-in
    /// AES-GCM XML encryptor when no certificate or KMS hook is configured.
    /// </summary>
    public string? MasterKey { get; set; }

    /// <summary>
    /// X.509 certificate options. If <see cref="DataProtectionCertificateOptions.Thumbprint"/>
    /// or <see cref="DataProtectionCertificateOptions.PfxPath"/> is set, the certificate-based
    /// encryptor is used. Takes precedence over <see cref="MasterKey"/>.
    /// </summary>
    public DataProtectionCertificateOptions Certificate { get; set; } = new();

    /// <summary>
    /// Optional callback that returns a custom <c>IXmlEncryptor</c>. The
    /// <c>IServiceProvider</c> argument is the application root provider — caller can resolve
    /// any registered service. Takes precedence over <see cref="MasterKey"/> and
    /// <see cref="Certificate"/>. Use this hook for KMS-backed encryptors.
    /// </summary>
    public Func<IServiceProvider, Microsoft.AspNetCore.DataProtection.XmlEncryption.IXmlEncryptor>? CustomEncryptorFactory { get; set; }

    /// <summary>
    /// True when at least one of the three variants is configured.
    /// </summary>
    public bool HasEncryptorConfigured =>
        CustomEncryptorFactory is not null
        || Certificate.IsConfigured
        || !string.IsNullOrWhiteSpace(MasterKey);
}

/// <summary>
/// X.509 certificate selector for the DataProtection key-ring encryptor.
/// Either <see cref="Thumbprint"/> (local store lookup) or <see cref="PfxPath"/>
/// (file on disk, optional password) must be set. If both are set, the PFX path wins.
/// </summary>
public sealed class DataProtectionCertificateOptions
{
    /// <summary>SHA-1 (or SHA-256) thumbprint of the certificate to look up. Case- and whitespace-insensitive.</summary>
    public string? Thumbprint { get; set; }

    /// <summary>Certificate store name when looking up by thumbprint. Default: <c>My</c>.</summary>
    public string StoreName { get; set; } = "My";

    /// <summary>
    /// Certificate store location. Default: <c>CurrentUser</c>. Use <c>LocalMachine</c>
    /// when running as a service account that doesn't have a personal user store.
    /// </summary>
    public string StoreLocation { get; set; } = "CurrentUser";

    /// <summary>Path to a PFX/PKCS#12 file on disk. Mutually exclusive-ish with <see cref="Thumbprint"/>.</summary>
    public string? PfxPath { get; set; }

    /// <summary>Password for the PFX file. Leave <c>null</c> for password-less PFX.</summary>
    public string? PfxPassword { get; set; }

    /// <summary>True when at least one source is set (thumbprint or PFX path).</summary>
    public bool IsConfigured =>
        !string.IsNullOrWhiteSpace(Thumbprint) || !string.IsNullOrWhiteSpace(PfxPath);
}
