using MyCSharp.HttpUserAgentParser;
using MyCSharp.HttpUserAgentParser.Providers;
using redb.Route.Abstractions;

namespace redb.Identity.Core.Services;

/// <summary>
/// Device-identification fields captured from an authentication exchange: sanitized
/// client IP, raw <c>User-Agent</c> string, and a human-friendly parsed device label
/// (browser + OS family). All fields are optional — non-HTTP transports (CLI, test
/// harnesses) produce all-nulls without failing authentication.
/// </summary>
internal readonly record struct DeviceMetadata(string? IpAddress, string? UserAgent, string? DeviceLabel)
{
    public static readonly DeviceMetadata Empty = new(null, null, null);
}

/// <summary>
/// Reads client-IP and <c>User-Agent</c> from the inbound exchange headers (as populated
/// by <c>HttpConsumer</c> and sanitized by <c>TrustedProxyResolverProcessor</c>) and
/// derives a display-friendly device label via <see cref="IHttpUserAgentParserProvider"/>.
/// </summary>
/// <remarks>
/// <para>The IP source is <c>redbHttp.RemoteAddress</c> — which <b>already reflects</b> the
/// real client after trusted-proxy resolution (see <c>TrustedProxyResolverProcessor</c>).
/// <c>X-Forwarded-For</c> is intentionally not read here to avoid a second, uncoordinated
/// trust decision.</para>
/// <para>The UA string is truncated to 512 characters before persistence to bound the PROPS
/// row payload against hostile or buggy clients sending megabyte-sized UA strings.</para>
/// <para>When no parser is registered (lean test host), <see cref="Extract"/> still
/// populates <c>IpAddress</c>/<c>UserAgent</c> and returns <c>DeviceLabel = null</c>.</para>
/// </remarks>
internal static class DeviceMetadataExtractor
{
    private const int UserAgentMaxLength = 512;

    public static DeviceMetadata Extract(IExchange? exchange, IHttpUserAgentParserProvider? parser)
    {
        if (exchange?.In is null) return DeviceMetadata.Empty;

        var headers = exchange.In.Headers;

        // redbHttp.RemoteAddress is populated by HttpConsumer from HttpContext.Connection
        // and — when ReverseProxyOptions.TrustForwardedFor=true and the socket peer is
        // whitelisted — replaced with the first untrusted hop of X-Forwarded-For by
        // TrustedProxyResolverProcessor. We consume it as-is here.
        string? ip = null;
        if (headers.TryGetValue("redbHttp.RemoteAddress", out var ipHdr) && ipHdr is not null)
            ip = ipHdr.ToString();

        string? ua = null;
        if (headers.TryGetValue("User-Agent", out var uaHdr) && uaHdr is not null)
        {
            ua = uaHdr.ToString();
            if (ua is { Length: > UserAgentMaxLength })
                ua = ua.Substring(0, UserAgentMaxLength);
        }

        return new DeviceMetadata(ip, ua, ParseLabel(ua, parser));
    }

    internal static string? ParseLabel(string? userAgent, IHttpUserAgentParserProvider? parser)
    {
        if (string.IsNullOrWhiteSpace(userAgent) || parser is null) return null;

        HttpUserAgentInformation info;
        try
        {
            info = parser.Parse(userAgent);
        }
        catch
        {
            // Parser is best-effort — a malformed UA must never fail the authentication
            // flow. Fall back to a safe truncated snippet so operators still see *something*
            // in the sessions UI.
            return Truncate(userAgent, 64);
        }

        var browser = string.IsNullOrEmpty(info.Name) ? null : info.Name!;
        var version = MajorVersion(info.Version);
        var platform = info.Platform?.Name;

        if (browser is null && platform is null)
            return Truncate(userAgent, 64);

        var left = browser is null
            ? "Unknown browser"
            : (version is null ? browser : $"{browser} {version}");
        var right = string.IsNullOrEmpty(platform) ? "unknown OS" : platform!;
        return $"{left} on {right}";
    }

    private static string? MajorVersion(string? fullVersion)
    {
        if (string.IsNullOrEmpty(fullVersion)) return null;
        var dot = fullVersion.IndexOf('.');
        return dot > 0 ? fullVersion.Substring(0, dot) : fullVersion;
    }

    private static string Truncate(string value, int maxLength)
        => value.Length <= maxLength ? value : value.Substring(0, maxLength);
}
