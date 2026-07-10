using FluentAssertions;
using Microsoft.Extensions.Time.Testing;
using redb.Identity.Core.Services;
using redb.Route.Redis;
using StackExchange.Redis;
using Xunit;

namespace redb.Identity.Tests.Services;

/// <summary>
/// C6 — Integration tests for <see cref="RedisFederationStateNonceStore"/> using a real
/// Redis at <c>localhost:6379</c>. Each test isolates its keys via a unique prefix
/// (Guid) so concurrent test runs do not interfere — no manual cleanup is required.
/// </summary>
[Trait("Category", "Integration")]
public sealed class RedisFederationStateNonceStoreIntegrationTests
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
            await using var conn = await ConnectionMultiplexer.ConnectAsync(SharedFactory.Build());
            return conn.IsConnected;
        }
        catch { return false; }
    }

    private static RedisFederationStateNonceStore MakeStore(string prefix)
        => new(SharedFactory, prefix);

    [Fact]
    public async Task TryConsumeAsync_FirstCall_ReturnsTrue()
    {
        if (!await IsRedisReachableAsync()) return;

        var prefix = $"redb:identity:fed:test:{Guid.NewGuid():N}:";
        await using var store = MakeStore(prefix);

        var jti = Guid.NewGuid().ToString("N");
        var consumed = await store.TryConsumeAsync(jti, TimeSpan.FromMinutes(5));

        consumed.Should().BeTrue();
    }

    [Fact]
    public async Task TryConsumeAsync_SecondCallSameJti_ReturnsFalse()
    {
        if (!await IsRedisReachableAsync()) return;

        var prefix = $"redb:identity:fed:test:{Guid.NewGuid():N}:";
        await using var store = MakeStore(prefix);

        var jti = Guid.NewGuid().ToString("N");
        var first = await store.TryConsumeAsync(jti, TimeSpan.FromMinutes(5));
        var second = await store.TryConsumeAsync(jti, TimeSpan.FromMinutes(5));

        first.Should().BeTrue();
        second.Should().BeFalse("the same jti must be rejected on replay");
    }

    [Fact]
    public async Task TryConsumeAsync_AfterTtlElapses_AllowsReuse()
    {
        if (!await IsRedisReachableAsync()) return;

        var prefix = $"redb:identity:fed:test:{Guid.NewGuid():N}:";
        await using var store = MakeStore(prefix);

        var jti = Guid.NewGuid().ToString("N");
        // Use a very short TTL so this test stays fast.
        var first = await store.TryConsumeAsync(jti, TimeSpan.FromSeconds(1));
        first.Should().BeTrue();

        // Wait slightly longer than the TTL so Redis evicts the key.
        await Task.Delay(TimeSpan.FromSeconds(1.5));

        var afterExpiry = await store.TryConsumeAsync(jti, TimeSpan.FromSeconds(1));
        afterExpiry.Should().BeTrue("once the key has expired, the same jti can be consumed again");
    }

    [Fact]
    public async Task TryConsumeAsync_DifferentJtis_AreIndependent()
    {
        if (!await IsRedisReachableAsync()) return;

        var prefix = $"redb:identity:fed:test:{Guid.NewGuid():N}:";
        await using var store = MakeStore(prefix);

        var a = await store.TryConsumeAsync(Guid.NewGuid().ToString("N"), TimeSpan.FromMinutes(1));
        var b = await store.TryConsumeAsync(Guid.NewGuid().ToString("N"), TimeSpan.FromMinutes(1));
        var c = await store.TryConsumeAsync(Guid.NewGuid().ToString("N"), TimeSpan.FromMinutes(1));

        a.Should().BeTrue();
        b.Should().BeTrue();
        c.Should().BeTrue();
    }
}
