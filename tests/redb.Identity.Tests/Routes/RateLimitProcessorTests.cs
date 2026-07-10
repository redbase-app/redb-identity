using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Routes.Processors;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;
using Xunit;

namespace redb.Identity.Tests.Routes;

/// <summary>
/// C1 — Verifies that <see cref="RateLimitProcessor"/> is a no-op when disabled, passes
/// requests below the limit, and short-circuits with HTTP 429 + Retry-After once the
/// configured ceiling is breached.
/// </summary>
public sealed class RateLimitProcessorTests
{
    private static IExchange MakeExchange(string ip)
    {
        var msg = new Message();
        msg.Headers["redbHttp.RemoteAddress"] = ip;
        return new Exchange(msg) { Pattern = ExchangePattern.InOnly };
    }

    private static IServiceProvider BuildSp(RateLimitOptions rl, IRateLimitStore store)
    {
        var opts = new RedbIdentityOptions { RateLimit = rl };
        var sc = new ServiceCollection();
        sc.AddSingleton<IRateLimitStore>(store);
        sc.AddSingleton<IOptions<RedbIdentityOptions>>(Options.Create(opts));
        return sc.BuildServiceProvider();
    }

    [Fact]
    public async Task Disabled_NoOp_DoesNotTouchExchange()
    {
        var rl = new RateLimitOptions { Enabled = false };
        using var store = new InMemoryRateLimitStore();
        var sp = BuildSp(rl, store);

        var p = new RateLimitProcessor(sp, "any", o => 1, _ => TimeSpan.FromMinutes(1));
        var ex = MakeExchange("1.2.3.4");
        await p.Process(ex);

        ex.Out.Should().BeNull();
    }

    [Fact]
    public async Task BelowLimit_DoesNotTouchExchange()
    {
        var rl = new RateLimitOptions { Enabled = true, PerIpPerMinute = 5 };
        using var store = new InMemoryRateLimitStore();
        var sp = BuildSp(rl, store);

        var p = new RateLimitProcessor(sp, "any", o => o.PerIpPerMinute, _ => TimeSpan.FromMinutes(1));
        var ex = MakeExchange("1.2.3.4");
        await p.Process(ex);

        ex.Out.Should().BeNull();
    }

    [Fact]
    public async Task OverLimit_Sets429_RetryAfter_AndStops()
    {
        var rl = new RateLimitOptions { Enabled = true, PerIpPerMinute = 1, DefaultRetryAfterSeconds = 60 };
        using var store = new InMemoryRateLimitStore();
        var sp = BuildSp(rl, store);

        var p = new RateLimitProcessor(sp, "any", o => o.PerIpPerMinute, _ => TimeSpan.FromMinutes(1));

        var ex1 = MakeExchange("1.2.3.4");
        await p.Process(ex1); // first hit — passes

        var ex2 = MakeExchange("1.2.3.4");
        await p.Process(ex2); // second hit — denied

        ex2.Out.Should().NotBeNull();
        ex2.Out!.Headers["redbHttp.ResponseCode"].Should().Be(429);
        ex2.Out.Headers["redbHttp.ResponseContentType"].Should().Be("application/json");
        ex2.Out.Headers.ContainsKey("Retry-After").Should().BeTrue();

        var body = ex2.Out.Body as IDictionary<string, object?>;
        body.Should().NotBeNull();
        body!["success"].Should().Be(false);
        body["error"].Should().Be("rate_limited");

        ex2.Exception.Should().BeOfType<RateLimitedException>();
        ex2.ExceptionHandled.Should().BeTrue();
    }

    // ── G4 — sliding-window recovery ──

    [Fact]
    public async Task PerIpBuckets_DistinctIPs_DoNotShareCounter()
    {
        // C1 contract: bucket key includes the IP. A spike from 1.2.3.4 must not block
        // unrelated 5.6.7.8 traffic.
        var rl = new RateLimitOptions { Enabled = true, PerIpPerMinute = 1, DefaultRetryAfterSeconds = 60 };
        using var store = new InMemoryRateLimitStore();
        var sp = BuildSp(rl, store);
        var p = new RateLimitProcessor(sp, "any", o => o.PerIpPerMinute, _ => TimeSpan.FromMinutes(1));

        var first = MakeExchange("1.2.3.4");
        var second = MakeExchange("1.2.3.4");
        var third = MakeExchange("5.6.7.8"); // different IP → independent bucket

        await p.Process(first);
        await p.Process(second);
        await p.Process(third);

        first.Out.Should().BeNull();
        second.Out!.Headers["redbHttp.ResponseCode"].Should().Be(429);
        third.Out.Should().BeNull("a different IP must not inherit the first IP's counter");
    }

    [Fact]
    public async Task SlidingWindow_RecoversAfterWindowExpires()
    {
        // C1 contract: counter is a sliding window, not a fixed bucket. Once the window
        // elapses since the recorded hit, a new attempt is allowed.
        var rl = new RateLimitOptions { Enabled = true, PerIpPerMinute = 1, DefaultRetryAfterSeconds = 60 };
        var clock = new Microsoft.Extensions.Time.Testing.FakeTimeProvider(
            startDateTime: new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        using var store = new InMemoryRateLimitStore(clock);
        var sp = BuildSp(rl, store);
        var p = new RateLimitProcessor(sp, "any", o => o.PerIpPerMinute, _ => TimeSpan.FromMinutes(1));

        var ex1 = MakeExchange("1.2.3.4");
        await p.Process(ex1); // first hit — passes
        ex1.Out.Should().BeNull();

        // Immediately retry → still throttled.
        var ex2 = MakeExchange("1.2.3.4");
        await p.Process(ex2);
        ex2.Out!.Headers["redbHttp.ResponseCode"].Should().Be(429);

        // Advance past the 1-minute window → bucket recovers.
        clock.Advance(TimeSpan.FromMinutes(1) + TimeSpan.FromSeconds(1));
        var ex3 = MakeExchange("1.2.3.4");
        await p.Process(ex3);
        ex3.Out.Should().BeNull("after the sliding window elapses the previous hit must be forgotten");
    }
}
