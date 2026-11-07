namespace redb.Identity.Core.Configuration;

/// <summary>
/// Governs how the server fetches a <b>client's</b> JWKS from its <c>jwks_uri</c>
/// (RFC 7517), used to verify things the client signed: JAR request objects (RFC 9101)
/// and <c>private_key_jwt</c> assertions (RFC 7523).
/// <para>
/// <b>These are SSRF controls, not tuning knobs.</b> The URL comes from the client record,
/// so a fetch makes the server issue an outbound request to an address someone else chose.
/// Without the restrictions below that is a probe into the internal network — including cloud
/// metadata endpoints such as <c>169.254.169.254</c>, which hand out credentials to anyone
/// who can reach them. Loosen them only for local development.
/// </para>
/// </summary>
public sealed class ClientKeysOptions
{
    /// <summary>
    /// How long a fetched JWKS is reused before a background refresh. Default: 12 hours.
    /// A <c>kid</c> miss triggers one immediate out-of-band refresh regardless of this value,
    /// so client key rotation is picked up without waiting for the TTL.
    /// </summary>
    public TimeSpan CacheLifetime { get; set; } = TimeSpan.FromHours(12);

    /// <summary>
    /// Minimum interval between forced refreshes of the same URL. Bounds how often an
    /// unauthenticated caller can make us fetch by replaying requests with unknown <c>kid</c>s.
    /// Default: 5 minutes.
    /// </summary>
    public TimeSpan MinimumRefreshInterval { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Timeout for a single JWKS fetch. Default: 5 seconds — an authorization request is
    /// waiting on it, so this must stay short.
    /// </summary>
    public TimeSpan FetchTimeout { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Maximum accepted JWKS document size in bytes. Default: 512 KiB. A real key set is a
    /// few KiB; the cap stops a hostile endpoint from streaming an endless body at us.
    /// </summary>
    public int MaxDocumentBytes { get; set; } = 512 * 1024;

    /// <summary>
    /// Require <c>https</c> for <c>jwks_uri</c>. Default: true.
    /// <b>Only</b> set to false for local development against a plain-HTTP test client —
    /// over HTTP the key set can be swapped in transit, which defeats the signature check
    /// it is supposed to anchor.
    /// </summary>
    public bool RequireHttps { get; set; } = true;

    /// <summary>
    /// Allow <c>jwks_uri</c> to resolve to loopback, private (RFC 1918), link-local or
    /// otherwise non-public addresses. Default: false.
    /// <b>Only</b> enable for local development or integration tests that host a JWKS on
    /// <c>localhost</c>; in production this is the difference between an outbound fetch and
    /// an internal port scan driven by whoever can edit a client record.
    /// </summary>
    public bool AllowPrivateNetworkTargets { get; set; }
}
