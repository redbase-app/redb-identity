using redb.Identity.Contracts.Configuration;

namespace redb.Identity.Http;

/// <summary>
/// Configuration options for Identity HTTP transport facade.
/// All HTTP-cosmetic settings (paths, branding, cookies, feature toggles for HTTP routes,
/// federation provider list) live here so the facade is operationally independent from
/// <c>RedbIdentityOptions</c> in Core. Cross-process state (DataProtection, persistence,
/// signing keys, etc.) still flows through <c>direct-vm://</c> calls into Core.
/// </summary>
public class IdentityTransportOptions
{
    /// <summary>HTTP-specific transport settings (ports, CORS).</summary>
    public HttpTransportOptions Http { get; set; } = new();

    /// <summary>
    /// Cross-module shared options (Issuer + Features). Same instance type as
    /// <c>RedbIdentityOptions.Shared</c> (defined in <c>redb.Identity.Contracts</c>).
    /// In-process test fixtures can simply assign
    /// <c>transportOptions.Shared = identityOptions.Shared</c> to ensure exact
    /// alignment instead of mirroring individual properties.
    /// </summary>
    public IdentitySharedOptions Shared { get; set; } = new();

    /// <summary>
    /// Issuer URI for the identity server (used by HTTP discovery + cookie <c>Secure</c> detection).
    /// Proxy onto <see cref="Shared"/>.<see cref="IdentitySharedOptions.Issuer"/>.
    /// </summary>
    public Uri Issuer
    {
        get => Shared.Issuer;
        set => Shared.Issuer = value;
    }

    /// <summary>HTTP route paths for interactive pages (login, consent, MFA).</summary>
    public IdentityHttpPaths Paths { get; set; } = new();

    /// <summary>UI branding for built-in pages (title, logo, colors, custom CSS).</summary>
    public IdentityHttpBranding Branding { get; set; } = new();

    /// <summary>Cookie security defaults (name prefix, SameSite modes, session cookie name).</summary>
    public IdentityCookieOptions Cookies { get; set; } = new();

    /// <summary>Lifetime of the session cookie. Default: 8 hours.</summary>
    public TimeSpan SessionCookieLifetime { get; set; } = TimeSpan.FromHours(8);

    /// <summary>
    /// Name of the cookie that carries the per-flow federation browser-binding secret.
    /// Default: <c>redb_fed_b</c>.
    /// </summary>
    public string BindingCookieName { get; set; } = "redb_fed_b";

    /// <summary>
    /// Cross-module feature toggles. Proxy onto <see cref="Shared"/>.<see cref="IdentitySharedOptions.Features"/>.
    /// </summary>
    public IdentityFeatureFlags Features
    {
        get => Shared.Features;
        set => Shared.Features = value;
    }

    /// <summary>SCIM bulk-endpoint limits. Effective only when <see cref="IdentityFeatureFlags.EnableScimBulk"/> is true.</summary>
    public IdentityScimBulkOptions ScimBulk { get; set; } = new();

    /// <summary>
    /// Federation providers exposed on the login page. Provider <c>ClientSecret</c> values
    /// can be left empty here — the secret-bearing config lives in Core; this list only drives
    /// the HTTP-visible button rendering and callback dispatch table.
    /// </summary>
    public List<FederationProviderConfig> FederationProviders { get; set; } = [];
}

/// <summary>HTTP route paths for interactive pages.</summary>
public sealed class IdentityHttpPaths
{
    /// <summary>Path to the login page. Default: <c>/login</c>.</summary>
    public string Login { get; set; } = "/login";

    /// <summary>Path to the consent page. Default: <c>/consent</c>.</summary>
    public string Consent { get; set; } = "/consent";

    /// <summary>Path to the MFA verification page. Default: <c>/mfa</c>.</summary>
    public string Mfa { get; set; } = "/mfa";

    /// <summary>Path to the MFA recovery code page. Default: <c>/mfa/recovery</c>.</summary>
    public string MfaRecovery { get; set; } = "/mfa/recovery";
}

/// <summary>UI branding for built-in identity pages.</summary>
public sealed class IdentityHttpBranding
{
    /// <summary>Title shown on the login page. Default: <c>Sign In</c>.</summary>
    public string LoginTitle { get; set; } = "Sign In";

    /// <summary>URL of a logo image shown above the login form.</summary>
    public string? LogoUrl { get; set; }

    /// <summary>Primary color for buttons and accents. Default: <c>#2563eb</c>.</summary>
    public string PrimaryColor { get; set; } = "#2563eb";

    /// <summary>Primary color hover state. Default: <c>#1d4ed8</c>.</summary>
    public string PrimaryColorHover { get; set; } = "#1d4ed8";

    /// <summary>Extra CSS injected into every identity page.</summary>
    public string? CustomCss { get; set; }
}

/// <summary>SCIM bulk-endpoint transport limits.</summary>
public sealed class IdentityScimBulkOptions
{
    /// <summary>Maximum number of operations a single SCIM <c>/Bulk</c> request may carry. Default: 1000.</summary>
    public int MaxOperations { get; set; } = 1000;

    /// <summary>Maximum payload size (bytes) of a single SCIM <c>/Bulk</c> request. Default: 1 MiB.</summary>
    public int MaxPayloadSize { get; set; } = 1_048_576;
}

/// <summary>
/// HTTP transport settings (ports, CORS).
/// </summary>
public class HttpTransportOptions
{
    /// <summary>
    /// Port for public OIDC endpoints (<c>/connect/*</c>, <c>/.well-known/*</c>).
    /// Default: <c>8080</c>.
    /// </summary>
    public int PublicPort { get; set; } = 8080;

    /// <summary>
    /// Optional separate port for management API (<c>/api/v1/identity/*</c>).
    /// If <c>null</c>, management API shares <see cref="PublicPort"/>.
    /// Production recommendation: use a separate port (e.g., 8081) behind a firewall.
    /// </summary>
    public int? ManagementPort { get; set; }

    /// <summary>
    /// Master switch for CORS on browser-facing OIDC endpoints (<c>/.well-known/*</c>,
    /// <c>/connect/token</c>, <c>/connect/userinfo</c>, <c>/connect/revocation</c>,
    /// <c>/connect/introspect</c>, <c>/connect/logout</c>). Required for SPA / native PKCE
    /// clients calling these endpoints from a browser context.
    /// <para>
    /// Endpoints that perform browser redirects (<c>/connect/authorize</c>, <c>/login</c>,
    /// <c>/mfa</c>, <c>/consent</c>, federation callback) and the management API
    /// (<c>/api/v1/identity/*</c>, <c>/scim/*</c>) NEVER receive CORS headers regardless of this
    /// flag — those flows are not initiated from cross-origin <c>fetch</c>/<c>XHR</c>.
    /// </para>
    /// Default: <c>false</c>.
    /// </summary>
    public bool CorsEnabled { get; set; }

    /// <summary>
    /// When <c>true</c>, the registered-client origin resolver is wired up so that any browser
    /// <c>Origin</c> matching the redirect / post-logout URI of a registered OAuth application
    /// is allowed automatically. This is the recommended production setting: as new SPAs are
    /// onboarded via the management API they receive CORS access without any config change.
    /// <para>
    /// When <c>false</c>, only origins listed in <see cref="AdditionalAllowedOrigins"/> (or
    /// supplied programmatically via <see cref="CorsOriginsResolver"/>) are allowed.
    /// </para>
    /// Default: <c>true</c>.
    /// </summary>
    public bool CorsRegisteredClientOriginsEnabled { get; set; } = true;

    /// <summary>
    /// Comma-separated list of origins that should always be allowed in addition to those
    /// derived from registered clients. Useful for dev/staging fallbacks (e.g.
    /// <c>"http://localhost:3000, http://localhost:5173"</c>) or for browser-facing tooling
    /// that does not own its own OAuth client registration.
    /// </summary>
    public string? AdditionalAllowedOrigins { get; set; }

    /// <summary>
    /// Optional fully-programmatic CORS origin resolver. When set, this delegate completely
    /// replaces the registered-client resolver and <see cref="AdditionalAllowedOrigins"/> for
    /// every browser-facing OIDC endpoint. Useful for cases where origin policy is owned by
    /// an external policy engine.
    /// </summary>
    public Func<Microsoft.AspNetCore.Http.HttpRequest, string?>? CorsOriginsResolver { get; set; }

    /// <summary>
    /// Comma-separated allowed-origins list (legacy; pre-C15).
    /// </summary>
    /// <remarks>
    /// Deprecated: a static CSV cannot be combined with the registered-client resolver and
    /// browsers cannot consume CSV in <c>Access-Control-Allow-Origin</c>. Migrate to
    /// <see cref="AdditionalAllowedOrigins"/> (same semantics, now matched per-request and
    /// echoed as a single origin) or <see cref="CorsOriginsResolver"/> for full control.
    /// </remarks>
    [Obsolete("Use AdditionalAllowedOrigins (CSV, properly matched) or CorsOriginsResolver. " +
              "CorsOrigins is forwarded to AdditionalAllowedOrigins when set.")]
    public string? CorsOrigins { get; set; }

    /// <summary>
    /// Path for the OIDC federation callback endpoint.
    /// External IdPs redirect back to this path after user authentication.
    /// Default: <c>/connect/federation/callback</c>.
    /// </summary>
    public string FederationCallbackPath { get; set; } = "/connect/federation/callback";

    /// <summary>
    /// Computes the effective additional-origins CSV by concatenating the deprecated
    /// <see cref="CorsOrigins"/> (if any) with <see cref="AdditionalAllowedOrigins"/>.
    /// Centralised so the back-compat shim lives in one place.
    /// </summary>
    internal string? GetEffectiveAdditionalOrigins()
    {
#pragma warning disable CS0618 // legacy field deliberately read here
        var legacy = CorsOrigins;
#pragma warning restore CS0618
        if (string.IsNullOrEmpty(legacy)) return AdditionalAllowedOrigins;
        if (string.IsNullOrEmpty(AdditionalAllowedOrigins)) return legacy;
        return legacy + "," + AdditionalAllowedOrigins;
    }
}
