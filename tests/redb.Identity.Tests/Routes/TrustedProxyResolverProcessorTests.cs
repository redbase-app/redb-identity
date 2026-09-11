using System.Net;
using FluentAssertions;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Routes.Processors;
using redb.Route.Abstractions;
using redb.Route.Core;
using Xunit;

namespace redb.Identity.Tests.Routes;

/// <summary>
/// C2 — Verifies that <see cref="TrustedProxyResolverProcessor"/> sanitizes the
/// <c>redbHttp.RemoteAddress</c> header according to the secure-by-default trust model
/// described on <see cref="ReverseProxyOptions"/>.
/// </summary>
public sealed class TrustedProxyResolverProcessorTests
{
    private const string SocketIpHeader = "redbHttp.RemoteAddress";
    private const string XForwardedFor = "X-Forwarded-For";

    private static IExchange MakeExchange(string socketIp, string? xForwardedFor)
    {
        var msg = new Message();
        msg.Headers[SocketIpHeader] = socketIp;
        if (xForwardedFor is not null)
            msg.Headers[XForwardedFor] = xForwardedFor;
        return new Exchange(msg) { Pattern = ExchangePattern.InOnly };
    }

    [Fact]
    public async Task TrustForwardedForFalse_DoesNothing_EvenWithProxyWhitelisted()
    {
        var opts = new ReverseProxyOptions
        {
            TrustForwardedFor = false,
            KnownProxies = { IPAddress.Parse("10.0.0.1") }
        };
        var sut = new TrustedProxyResolverProcessor(opts);
        var ex = MakeExchange("10.0.0.1", "1.2.3.4");

        await sut.Process(ex);

        ex.In.Headers[SocketIpHeader].Should().Be("10.0.0.1");
    }

    [Fact]
    public async Task UntrustedSocketPeer_IgnoresXForwardedFor()
    {
        // The peer is NOT in the whitelist — XFF can be spoofed and must be discarded.
        var opts = new ReverseProxyOptions
        {
            TrustForwardedFor = true,
            KnownProxies = { IPAddress.Parse("10.0.0.1") }
        };
        var sut = new TrustedProxyResolverProcessor(opts);
        var ex = MakeExchange("203.0.113.99", "1.2.3.4");

        await sut.Process(ex);

        ex.In.Headers[SocketIpHeader].Should().Be("203.0.113.99");
    }

    [Fact]
    public async Task TrustedSocketPeer_OverwritesWithRightmostUntrustedHop()
    {
        var opts = new ReverseProxyOptions
        {
            TrustForwardedFor = true,
            KnownProxies = { IPAddress.Parse("10.0.0.1") }
        };
        var sut = new TrustedProxyResolverProcessor(opts);
        var ex = MakeExchange("10.0.0.1", "1.2.3.4");

        await sut.Process(ex);

        ex.In.Headers[SocketIpHeader].Should().Be("1.2.3.4");
    }

    [Fact]
    public async Task MultiHopChain_SkipsTrustedHopsRightToLeft()
    {
        // Two trusted proxies in series; the real client is the leftmost untrusted IP.
        var opts = new ReverseProxyOptions
        {
            TrustForwardedFor = true,
            KnownProxies = { IPAddress.Parse("10.0.0.1"), IPAddress.Parse("10.0.0.2") }
        };
        var sut = new TrustedProxyResolverProcessor(opts);
        var ex = MakeExchange("10.0.0.1", "1.2.3.4, 10.0.0.2");

        await sut.Process(ex);

        ex.In.Headers[SocketIpHeader].Should().Be("1.2.3.4");
    }

    [Fact]
    public async Task KnownNetworks_CidrMatch_TreatsPeerAsTrusted()
    {
        var opts = new ReverseProxyOptions
        {
            TrustForwardedFor = true,
            KnownNetworks = { IPNetwork.Parse("10.0.0.0/24") }
        };
        var sut = new TrustedProxyResolverProcessor(opts);
        var ex = MakeExchange("10.0.0.42", "1.2.3.4");

        await sut.Process(ex);

        ex.In.Headers[SocketIpHeader].Should().Be("1.2.3.4");
    }

    [Fact]
    public async Task ChainEntirelyTrusted_LeavesSocketIpUnchanged()
    {
        var opts = new ReverseProxyOptions
        {
            TrustForwardedFor = true,
            KnownProxies = { IPAddress.Parse("10.0.0.1"), IPAddress.Parse("10.0.0.2") }
        };
        var sut = new TrustedProxyResolverProcessor(opts);
        var ex = MakeExchange("10.0.0.1", "10.0.0.2");

        await sut.Process(ex);

        ex.In.Headers[SocketIpHeader].Should().Be("10.0.0.1");
    }

    [Fact]
    public async Task NoXForwardedFor_LeavesHeaderUnchanged()
    {
        var opts = new ReverseProxyOptions
        {
            TrustForwardedFor = true,
            KnownProxies = { IPAddress.Parse("10.0.0.1") }
        };
        var sut = new TrustedProxyResolverProcessor(opts);
        var ex = MakeExchange("10.0.0.1", null);

        await sut.Process(ex);

        ex.In.Headers[SocketIpHeader].Should().Be("10.0.0.1");
    }

    [Fact]
    public async Task IPv4WithPort_StripsPort()
    {
        var opts = new ReverseProxyOptions
        {
            TrustForwardedFor = true,
            KnownProxies = { IPAddress.Parse("10.0.0.1") }
        };
        var sut = new TrustedProxyResolverProcessor(opts);
        var ex = MakeExchange("10.0.0.1", "1.2.3.4:54321");

        await sut.Process(ex);

        ex.In.Headers[SocketIpHeader].Should().Be("1.2.3.4");
    }

    [Fact]
    public async Task IPv6BracketWithPort_StripsBracketsAndPort()
    {
        var opts = new ReverseProxyOptions
        {
            TrustForwardedFor = true,
            KnownProxies = { IPAddress.Parse("10.0.0.1") }
        };
        var sut = new TrustedProxyResolverProcessor(opts);
        var ex = MakeExchange("10.0.0.1", "[2001:db8::1]:443");

        await sut.Process(ex);

        ex.In.Headers[SocketIpHeader].Should().Be("2001:db8::1");
    }

    [Fact]
    public async Task UnparseableHop_StopsTheWalk_KeepsSocketIp()
    {
        // "unknown" is a legal RFC 7239 identifier a proxy may write for a peer it could not name.
        // It must END the walk. Skipping it would carry the walk left into "203.0.113.7", which in
        // this header is the client-supplied part, and hand the client its own throttle bucket.
        var opts = new ReverseProxyOptions
        {
            TrustForwardedFor = true,
            KnownProxies = { IPAddress.Parse("10.0.0.1") }
        };
        var sut = new TrustedProxyResolverProcessor(opts);
        var ex = MakeExchange("10.0.0.1", "203.0.113.7, unknown");

        await sut.Process(ex);

        ex.In.Headers[SocketIpHeader].Should().Be("10.0.0.1");
    }

    [Fact]
    public async Task HostAlreadyResolved_PeerNotInList_IsIdempotent()
    {
        // When the shared Kestrel host has already rewritten RemoteAddress to the client, the
        // processor sees a peer that is not a trusted proxy and must leave it alone. This is what
        // makes host-level and processor-level resolution safe to run together.
        var opts = new ReverseProxyOptions
        {
            TrustForwardedFor = true,
            KnownProxies = { IPAddress.Parse("10.0.0.1") }
        };
        var sut = new TrustedProxyResolverProcessor(opts);
        var ex = MakeExchange("203.0.113.7", "203.0.113.7, 10.0.0.9");

        await sut.Process(ex);

        ex.In.Headers[SocketIpHeader].Should().Be("203.0.113.7");
    }
}
