using System.Net;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using redb.Identity.Core.Configuration;
using redb.Route.Abstractions;
using redb.Route.Http;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// C2 — Sanitizes the <c>redbHttp.RemoteAddress</c> exchange header before per-IP
/// throttling (C1) and other client-IP-aware logic observe it.
/// </summary>
/// <remarks>
/// <para>
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
/// </para>
/// <para>
/// The walk itself is <see cref="ForwardedHeaderResolver"/> from the shared HTTP host: one
/// implementation of the trust model for the whole ecosystem, including its rule that an entry
/// which does not parse ends the walk rather than being skipped. The primary place for this
/// resolution is the host (<c>HttpHostingOptions.TrustedProxies</c>), which rewrites the address
/// and the scheme before any consumer runs. This processor remains for a context whose host did
/// not resolve, and it is idempotent after the host did: the address it then sees is the client's,
/// which is not a trusted proxy, so it leaves it alone.
/// </para>
/// </remarks>
internal sealed class TrustedProxyResolverProcessor : IProcessor
{
    private readonly ReverseProxyOptions _options;
    private readonly TrustedProxyOptions _trust;
    private readonly ILogger _logger;

    public TrustedProxyResolverProcessor(ReverseProxyOptions options, ILogger? logger = null)
    {
        _options = options;
        _logger = logger ?? NullLogger.Instance;

        _trust = new TrustedProxyOptions();
        foreach (var ip in options.KnownProxies) _trust.KnownProxies.Add(TrustedProxyOptions.Normalize(ip));
        foreach (var net in options.KnownNetworks) _trust.KnownNetworks.Add(net);
    }

    public Task Process(IExchange exchange, CancellationToken ct = default)
    {
        if (!_options.TrustForwardedFor)
            return Task.CompletedTask;

        if (!exchange.In.Headers.TryGetValue("redbHttp.RemoteAddress", out var rawSocket)
            || rawSocket is not string socketIpStr
            || !IPAddress.TryParse(socketIpStr, out var socketIp))
            return Task.CompletedTask;

        if (!_trust.IsTrusted(socketIp))
        {
            _logger.LogDebug(
                "TrustedProxyResolver: socket peer {SocketIp} is not whitelisted; X-Forwarded-For ignored",
                socketIpStr);
            return Task.CompletedTask;
        }

        var forwardedFor = exchange.In.Headers.TryGetValue(ForwardedHeaderResolver.ForwardedFor, out var raw)
            ? raw?.ToString()
            : null;

        var resolved = ForwardedHeaderResolver.Resolve(socketIp, forwardedFor, forwardedProto: null, _trust);
        if (!resolved.AddressApplied || resolved.ClientAddress is null)
            return Task.CompletedTask;

        exchange.In.Headers["redbHttp.RemoteAddress"] = resolved.ClientAddress.ToString();
        _logger.LogDebug(
            "TrustedProxyResolver: socket peer {SocketIp} is trusted; resolved client IP from X-Forwarded-For: {ClientIp}",
            socketIpStr, resolved.ClientAddress);
        return Task.CompletedTask;
    }
}
