using System.Net;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using redb.Identity.Core.Configuration;
using redb.Route.Abstractions;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// C2 — Sanitizes the <c>redbHttp.RemoteAddress</c> exchange header before per-IP
/// throttling (C1) and other client-IP-aware logic observe it.
/// </summary>
/// <remarks>
/// Behavior is controlled by <see cref="ReverseProxyOptions"/>:
/// <list type="bullet">
///   <item><description>If <c>TrustForwardedFor=false</c> (default) — does nothing,
///   <c>RemoteAddress</c> remains the immediate socket peer.</description></item>
///   <item><description>If <c>TrustForwardedFor=true</c> AND the socket peer is whitelisted
///   in <c>KnownProxies</c> / <c>KnownNetworks</c> — walks <c>X-Forwarded-For</c>
///   right-to-left, skipping further whitelisted hops, and overwrites
///   <c>RemoteAddress</c> with the first untrusted IP.</description></item>
///   <item><description>If <c>TrustForwardedFor=true</c> but the socket peer is NOT
///   whitelisted — does nothing (an attacker cannot forge <c>X-Forwarded-For</c> from an
///   untrusted hop).</description></item>
/// </list>
/// Implements the same trust model as ASP.NET Core's <c>ForwardedHeadersMiddleware</c> but
/// works at the redb.Route processor layer, which is the only layer redb.Identity owns.
/// </remarks>
internal sealed class TrustedProxyResolverProcessor : IProcessor
{
    private readonly ReverseProxyOptions _options;
    private readonly ILogger _logger;

    public TrustedProxyResolverProcessor(ReverseProxyOptions options, ILogger? logger = null)
    {
        _options = options;
        _logger = logger ?? NullLogger.Instance;
    }

    public Task Process(IExchange exchange, CancellationToken ct = default)
    {
        if (!_options.TrustForwardedFor)
            return Task.CompletedTask;

        if (!exchange.In.Headers.TryGetValue("redbHttp.RemoteAddress", out var rawSocket)
            || rawSocket is not string socketIpStr
            || !IPAddress.TryParse(socketIpStr, out var socketIp))
            return Task.CompletedTask;

        if (!IsTrustedProxy(socketIp))
        {
            _logger.LogDebug(
                "TrustedProxyResolver: socket peer {SocketIp} is not whitelisted; X-Forwarded-For ignored",
                socketIpStr);
            return Task.CompletedTask;
        }

        if (!TryGetForwardedForChain(exchange, out var chain) || chain.Count == 0)
            return Task.CompletedTask;

        // Walk right-to-left: the rightmost entry is the IP the *trusted* proxy itself saw
        // as its client. If THAT IP is also trusted (multi-hop), continue walking left
        // until we hit the first untrusted IP — that's the real client.
        for (var i = chain.Count - 1; i >= 0; i--)
        {
            if (!IPAddress.TryParse(chain[i], out var hop))
                continue;

            if (IsTrustedProxy(hop))
                continue;

            exchange.In.Headers["redbHttp.RemoteAddress"] = hop.ToString();
            _logger.LogDebug(
                "TrustedProxyResolver: socket peer {SocketIp} is trusted; resolved client IP from X-Forwarded-For: {ClientIp}",
                socketIpStr, hop);
            return Task.CompletedTask;
        }

        // Whole chain consists of trusted hops; leave the socket IP in place.
        return Task.CompletedTask;
    }

    private bool IsTrustedProxy(IPAddress ip)
    {
        foreach (var known in _options.KnownProxies)
        {
            if (known.Equals(ip)) return true;
        }
        foreach (var network in _options.KnownNetworks)
        {
            if (network.Contains(ip)) return true;
        }
        return false;
    }

    private static bool TryGetForwardedForChain(IExchange exchange, out List<string> chain)
    {
        chain = new List<string>();
        if (!exchange.In.Headers.TryGetValue("X-Forwarded-For", out var raw) || raw is null)
            return false;

        var s = raw.ToString();
        if (string.IsNullOrWhiteSpace(s))
            return false;

        foreach (var part in s.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            // Strip optional :port (IPv4) or [v6]:port suffix produced by some proxies.
            var token = part;
            if (token.StartsWith('[') && token.Contains(']'))
            {
                var end = token.IndexOf(']');
                token = token.Substring(1, end - 1);
            }
            else if (token.Count(c => c == ':') == 1)
            {
                // IPv4:port — strip port. Bare IPv6 has multiple colons; leave as-is.
                token = token.Split(':')[0];
            }
            chain.Add(token);
        }
        return chain.Count > 0;
    }
}
