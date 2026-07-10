using FluentAssertions;
using Microsoft.Extensions.Time.Testing;
using redb.Identity.Core.Services;
using redb.Route.Redis;
using StackExchange.Redis;
using Xunit;

namespace redb.Identity.Tests.Services;

/// <summary>
/// C1 — Integration tests for <see cref="RedisRateLimitStore"/> using a real Redis at
/// <c>localhost:6379</c>. Each test isolates its keys via a unique prefix (Guid) so
/// concurrent test runs and any pre-existing keys do not interfere — no manual cleanup
/// is required.
/// </summary>
[Trait("Category", "Integration")]
public sealed class RedisRateLimitStoreIntegrationTests
{
    private const string RedisConnString = "localhost:6379";

    private static readonly RedisConnectionFactory SharedFactory = new()
    {
        ConnectionString = RedisConnString,
        AbortOnConnectFail = false,
        ConnectTimeout = 1000,
        SyncTimeout = 1000
    };

    private static async Task<bool> IsRedisReachableAsync()
    {
        try
        {
            // Probe via the same configuration the store will use, so shared options
            // (timeouts, SSL, client name) are honoured by the reachability check too.
            await using var conn = await ConnectionMultiplexer.ConnectAsync(SharedFactory.Build());
            return conn.IsConnected;
        }
        catch { return false; }
    }

    private static RedisRateLimitStore MakeStore(TimeProvider tp, string prefix)
        => new(SharedFactory, prefix, tp);

    [Fact]
    public async Task SlidingWindow_FirstHitsAllowed_ThenLimitBreached()
    {
        if (!await IsRedisReachableAsync())
            return; // Skip when redis is not available locally.

        var prefix = $"redb:identity:rl:test:{Guid.NewGuid():N}:";
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        await using var store = MakeStore(time, prefix);

        var key = "ip:any:1.2.3.4";
        for (int i = 1; i <= 3; i++)
        {
            var d = await store.TryIncrementAsync(key, limit: 3, window: TimeSpan.FromMinutes(1));
            d.Allowed.Should().BeTrue($"hit {i}/3 must pass");
            d.Count.Should().Be(i);
        }

        var denied = await store.TryIncrementAsync(key, 3, TimeSpan.FromMinutes(1));
        denied.Allowed.Should().BeFalse();
        denied.RetryAfter.Should().BeGreaterThan(TimeSpan.Zero);
        // Allow small tolerance for clock skew between FakeTimeProvider (C#) and Redis server time used by Lua.
        denied.RetryAfter.Should().BeLessThanOrEqualTo(TimeSpan.FromMinutes(1) + TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task ResetAsync_ClearsBucket()
    {
        if (!await IsRedisReachableAsync())
            return;

        var prefix = $"redb:identity:rl:test:{Guid.NewGuid():N}:";
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        await using var store = MakeStore(time, prefix);

        var key = "ipuser:login:1.2.3.4:alice";
        for (int i = 0; i < 3; i++)
            await store.TryIncrementAsync(key, 3, TimeSpan.FromMinutes(1));

        await store.ResetAsync(key);

        var afterReset = await store.TryIncrementAsync(key, 3, TimeSpan.FromMinutes(1));
        afterReset.Allowed.Should().BeTrue();
        afterReset.Count.Should().Be(1);
    }

    [Fact]
    public async Task IndependentKeys_HaveIndependentBuckets()
    {
        if (!await IsRedisReachableAsync())
            return;

        var prefix = $"redb:identity:rl:test:{Guid.NewGuid():N}:";
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        await using var store = MakeStore(time, prefix);

        for (int i = 0; i < 3; i++)
            await store.TryIncrementAsync("ip:any:10.0.0.1", 3, TimeSpan.FromMinutes(1));

        // Different IP — should not be affected.
        var other = await store.TryIncrementAsync("ip:any:10.0.0.2", 3, TimeSpan.FromMinutes(1));
        other.Allowed.Should().BeTrue();
        other.Count.Should().Be(1);
    }
}
