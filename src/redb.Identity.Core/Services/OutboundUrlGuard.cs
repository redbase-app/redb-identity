using System.Net;
using System.Net.Sockets;

namespace redb.Identity.Core.Services;

/// <summary>
/// Decides whether the server may make an outbound HTTP request to a URL that came from
/// <b>outside</b> — a client's <c>jwks_uri</c>, a JAR <c>request_uri</c>, a webhook target.
/// <para>
/// Such a URL is attacker-influenced input. Fetching it unchecked turns the server into a proxy
/// into its own network (SSRF): <c>http://127.0.0.1:9090/admin</c>, <c>http://10.0.0.5/</c>, or
/// the cloud metadata service at <c>169.254.169.254</c>, which hands out instance credentials to
/// whoever can reach it. The server is inside the perimeter; the caller is not.
/// </para>
/// </summary>
internal static class OutboundUrlGuard
{
    /// <summary>Why a URL was rejected. <see cref="None"/> means it passed.</summary>
    internal enum Rejection
    {
        None,
        NotAbsolute,
        SchemeNotAllowed,
        HttpsRequired,
        HostUnresolvable,
        PrivateNetworkTarget,
    }

    /// <summary>
    /// Validates the URL's shape (absolute, allowed scheme) without touching the network.
    /// </summary>
    internal static Rejection ValidateShape(string? url, bool requireHttps, out Uri? uri)
    {
        uri = null;
        if (string.IsNullOrWhiteSpace(url)) return Rejection.NotAbsolute;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var parsed)) return Rejection.NotAbsolute;

        if (parsed.Scheme != Uri.UriSchemeHttps && parsed.Scheme != Uri.UriSchemeHttp)
            return Rejection.SchemeNotAllowed;

        if (requireHttps && parsed.Scheme != Uri.UriSchemeHttps)
            return Rejection.HttpsRequired;

        uri = parsed;
        return Rejection.None;
    }

    /// <summary>
    /// Full check: shape, then DNS resolution, then every resolved address against the
    /// non-public ranges. Rejects when <b>any</b> resolved address is non-public — a name that
    /// answers with both a public and a private address must not slip through on the public one.
    /// </summary>
    /// <remarks>
    /// This cannot close DNS rebinding on its own: the name is resolved here and again by the
    /// HTTP stack, and the answer may differ between the two. Closing that hole means pinning the
    /// validated address for the actual connection. The check still removes the whole class of
    /// trivially-internal targets, which is what an operator pasting an internal URL — or an
    /// attacker with write access to a client record — would reach for first.
    /// </remarks>
    internal static async ValueTask<Rejection> ValidateAsync(
        string? url,
        bool requireHttps,
        bool allowPrivateNetworkTargets,
        CancellationToken cancellationToken = default)
    {
        var shape = ValidateShape(url, requireHttps, out var uri);
        if (shape != Rejection.None || uri is null) return shape;

        if (allowPrivateNetworkTargets) return Rejection.None;

        IPAddress[] addresses;
        if (IPAddress.TryParse(uri.Host, out var literal))
        {
            addresses = [literal];
        }
        else
        {
            try
            {
                addresses = await Dns.GetHostAddressesAsync(uri.Host, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception e) when (e is SocketException or ArgumentException)
            {
                return Rejection.HostUnresolvable;
            }
        }

        if (addresses.Length == 0) return Rejection.HostUnresolvable;

        foreach (var address in addresses)
        {
            if (!IsPublic(address)) return Rejection.PrivateNetworkTarget;
        }

        return Rejection.None;
    }

    /// <summary>
    /// True when the address is routable on the public internet. Everything else — loopback,
    /// RFC 1918, link-local (incl. the <c>169.254.169.254</c> metadata address), CGNAT,
    /// unique-local IPv6, and IPv4-mapped IPv6 forms of all of those — is treated as internal.
    /// </summary>
    private static bool IsPublic(IPAddress address)
    {
        // ::ffff:10.0.0.1 must be judged as 10.0.0.1, not as an opaque IPv6 address.
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();

        if (IPAddress.IsLoopback(address)) return false;

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = address.GetAddressBytes();
            return b[0] switch
            {
                0 => false,                                  // 0.0.0.0/8 "this network"
                10 => false,                                 // RFC 1918
                127 => false,                                // loopback (belt and braces)
                169 when b[1] == 254 => false,               // link-local incl. cloud metadata
                172 when b[1] >= 16 && b[1] <= 31 => false,  // RFC 1918
                192 when b[1] == 168 => false,               // RFC 1918
                100 when b[1] >= 64 && b[1] <= 127 => false, // RFC 6598 CGNAT
                >= 224 => false,                             // multicast + reserved
                _ => true,
            };
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast)
                return false;

            // fc00::/7 unique local
            var b = address.GetAddressBytes();
            if ((b[0] & 0xFE) == 0xFC) return false;

            // :: and ::1
            if (address.Equals(IPAddress.IPv6Any) || address.Equals(IPAddress.IPv6Loopback))
                return false;

            return true;
        }

        return false;
    }

    /// <summary>Human-readable reason, for logs and <c>invalid_request_object</c> descriptions.</summary>
    internal static string Describe(Rejection rejection) => rejection switch
    {
        Rejection.NotAbsolute => "not an absolute URL",
        Rejection.SchemeNotAllowed => "scheme must be http or https",
        Rejection.HttpsRequired => "must use https",
        Rejection.HostUnresolvable => "host could not be resolved",
        Rejection.PrivateNetworkTarget => "resolves to a non-public address",
        _ => "ok",
    };
}
