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
/// C1 — Verifies that <see cref="LoginFailureRecorderProcessor"/> increments the per-IP+
/// username failure bucket on bad logins, resets it on success, and emits HTTP 429 once
/// the configured ceiling is reached.
/// </summary>
public sealed class LoginFailureRecorderProcessorTests
{
    private static IExchange MakeExchange(string ip, string username, bool success)
    {
        var msg = new Message
        {
            Body = new Dictionary<string, object?> { ["username"] = username }
        };
        msg.Headers["redbHttp.RemoteAddress"] = ip;
        var ex = new Exchange(msg) { Pattern = ExchangePattern.InOut };
        ex.Out = new Message
        {
            Body = new Dictionary<string, object?> { ["success"] = success }
        };
        return ex;
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
    public async Task SuccessfulLogin_ResetsBucket()
    {
        var rl = new RateLimitOptions { Enabled = true, PerIpUsernameFailures = 3, PerIpUsernameWindow = TimeSpan.FromMinutes(15) };
        using var store = new InMemoryRateLimitStore();
        var sp = BuildSp(rl, store);
        var p = new LoginFailureRecorderProcessor(sp);

        // Pre-fill 2 failures for "alice" from 1.1.1.1
        await p.Process(MakeExchange("1.1.1.1", "alice", success: false));
        await p.Process(MakeExchange("1.1.1.1", "alice", success: false));

        // Successful login should reset.
        await p.Process(MakeExchange("1.1.1.1", "alice", success: true));

        // Three more failures should still be allowed (bucket reset).
        for (int i = 0; i < 3; i++)
        {
            var ex = MakeExchange("1.1.1.1", "alice", success: false);
            await p.Process(ex);
            // Below ceiling (3) → outBody untouched, success still false (the original).
            (ex.Out!.Body as IDictionary<string, object?>)!["success"].Should().Be(false);
        }
    }

    [Fact]
    public async Task BreachingCeiling_Emits429()
    {
        var rl = new RateLimitOptions { Enabled = true, PerIpUsernameFailures = 2, PerIpUsernameWindow = TimeSpan.FromMinutes(15), DefaultRetryAfterSeconds = 30 };
        using var store = new InMemoryRateLimitStore();
        var sp = BuildSp(rl, store);
        var p = new LoginFailureRecorderProcessor(sp);

        await p.Process(MakeExchange("1.1.1.1", "alice", success: false));
        await p.Process(MakeExchange("1.1.1.1", "alice", success: false));

        var breach = MakeExchange("1.1.1.1", "alice", success: false);
        await p.Process(breach);

        breach.Out!.Headers["redbHttp.ResponseCode"].Should().Be(429);
        var body = breach.Out.Body as IDictionary<string, object?>;
        body!["error"].Should().Be("rate_limited");
        breach.Exception.Should().BeOfType<RateLimitedException>();
    }

    [Fact]
    public async Task DifferentUsername_HasIndependentBucket()
    {
        var rl = new RateLimitOptions { Enabled = true, PerIpUsernameFailures = 2, PerIpUsernameWindow = TimeSpan.FromMinutes(15) };
        using var store = new InMemoryRateLimitStore();
        var sp = BuildSp(rl, store);
        var p = new LoginFailureRecorderProcessor(sp);

        await p.Process(MakeExchange("1.1.1.1", "alice", success: false));
        await p.Process(MakeExchange("1.1.1.1", "alice", success: false));

        // bob from same IP must not be blocked by alice's bucket.
        var bob = MakeExchange("1.1.1.1", "bob", success: false);
        await p.Process(bob);
        bob.Out!.Headers.ContainsKey("Retry-After").Should().BeFalse();
    }
}
