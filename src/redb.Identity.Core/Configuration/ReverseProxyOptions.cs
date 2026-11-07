using System.Net;

namespace redb.Identity.Core.Configuration;

/// <summary>
/// C2 — Configuration for the trusted-reverse-proxy whitelist consulted by
/// <see cref="Routes.Processors.TrustedProxyResolverProcessor"/>.
/// </summary>
/// <remarks>
/// Secure-by-default: with <see cref="TrustForwardedFor"/> <c>= false</c> (the default),
/// the resolver ignores all <c>X-Forwarded-For</c> / <c>Forwarded</c> headers and the
/// socket IP carried by <c>redbHttp.RemoteAddress</c> is propagated unchanged. This means
/// per-IP throttling (C1) sees only the immediate TCP peer — correct when the service is
/// exposed directly. Enable forwarded-IP resolution only when the service sits behind a
/// trusted reverse proxy whose IPs are listed here; otherwise an attacker can spoof
/// <c>X-Forwarded-For</c> and bypass per-IP rate limits.
/// </remarks>
public sealed class ReverseProxyOptions
{
    /// <summary>
    /// When <c>true</c>, the resolver consults the <c>X-Forwarded-For</c> header on requests
    /// arriving from a peer in <see cref="KnownProxies"/> / <see cref="KnownNetworks"/>, walks
    /// the chain right-to-left skipping any further trusted hops, and uses the first untrusted
    /// IP as the client address. When <c>false</c> (default), the socket IP is used as-is.
    /// </summary>
    public bool TrustForwardedFor { get; set; }

    /// <summary>Individual IP addresses of trusted reverse proxies.</summary>
    public List<IPAddress> KnownProxies { get; set; } = new();

    /// <summary>CIDR networks of trusted reverse proxies.</summary>
    public List<IPNetwork> KnownNetworks { get; set; } = new();
}
