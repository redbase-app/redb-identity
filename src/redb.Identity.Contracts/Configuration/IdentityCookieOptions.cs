namespace redb.Identity.Contracts.Configuration;

/// <summary>
/// SameSite cookie modes per RFC 6265bis. <c>None</c> requires <c>Secure</c>.
/// </summary>
public enum CookieSameSiteMode
{
    /// <summary>Strictest: cookie not sent on any cross-site request, even top-level navigation.</summary>
    Strict,

    /// <summary>Default for most identity flows: sent on top-level GET cross-site navigations
    /// (needed for OAuth/OIDC redirects) but not on background sub-resource requests.</summary>
    Lax,

    /// <summary>Sent on all requests including third-party. Requires <c>Secure</c>.</summary>
    None
}

/// <summary>
/// C9 — cookie security defaults shared by every cookie Identity emits.
/// </summary>
public sealed class IdentityCookieOptions
{
    /// <summary>
    /// When <c>true</c>, applies the <c>__Host-</c> name prefix to identity cookies
    /// (which forces <c>Secure</c>, <c>Path=/</c>, no <c>Domain</c>). When the
    /// surrounding scheme is not https, the helper falls back to the bare name
    /// to avoid emitting an invalid cookie that browsers would silently drop.
    /// Default: <c>false</c> for backward compatibility — flipping it to <c>true</c>
    /// invalidates all existing session cookies (forces re-login). Recommended
    /// for new production deployments.
    /// </summary>
    public bool UseHostPrefix { get; set; } = false;

    /// <summary>
    /// SameSite mode for the main session cookie. <c>Lax</c> (default) is required
    /// for cross-site OAuth / federation top-level redirects to carry the session.
    /// <c>Strict</c> blocks those — set only if Identity is the sole entry point.
    /// </summary>
    public CookieSameSiteMode SessionSameSite { get; set; } = CookieSameSiteMode.Lax;

    /// <summary>
    /// SameSite mode for the per-flow federation browser-binding cookie. Must be
    /// <c>Lax</c> (default) so the cookie returns with the IdP's callback redirect.
    /// <c>Strict</c> would prevent the binding check from ever succeeding.
    /// </summary>
    public CookieSameSiteMode BindingSameSite { get; set; } = CookieSameSiteMode.Lax;

    /// <summary>
    /// Name of the encrypted session cookie. Default: <c>redb.identity.session</c>.
    /// When <see cref="UseHostPrefix"/> is enabled and the request is over https,
    /// the effective name becomes <c>__Host-{value}</c>.
    /// </summary>
    public string SessionCookieName { get; set; } = "redb.identity.session";
}
