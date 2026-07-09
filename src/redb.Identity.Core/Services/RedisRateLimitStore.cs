using redb.Identity.Core.Configuration;
using redb.Route.Redis;
using StackExchange.Redis;

namespace redb.Identity.Core.Services;

/// <summary>
/// C1 — Cluster-global sliding-window counter backed by a Redis sorted set.
/// Activated when <see cref="RateLimitOptions.Backend"/> is <c>"redis"</c>.
/// Uses the same <see cref="RedisConnectionFactory"/> abstraction as
/// <see cref="redb.Route.Redis.Repositories.RedisClaimCheckRepository"/>.
/// </summary>
internal sealed class RedisRateLimitStore : IRateLimitStore, IAsyncDisposable, IDisposable
{
    private readonly RedisConnectionFactory _factory;
    private readonly string _prefix;
    private readonly TimeProvider _timeProvider;
    private readonly SemaphoreSlim _connectionLock = new(1, 1);

    private IConnectionMultiplexer? _connection;

    // Sliding-window counter. Mirrors InMemoryRateLimitStore semantics:
    // a request is denied iff the bucket already holds >= limit non-expired hits, and the
    // current hit is NOT inserted in that case. Returns { allowed (1/0), countAfter, oldestScore }.
    private const string IncrLuaScript =
        """
        local key = KEYS[1]
        local nowTicks = tonumber(ARGV[1])
        local windowTicks = tonumber(ARGV[2])
        local limit = tonumber(ARGV[3])
        local ttl = math.floor(windowTicks / 10000000) + 10
        redis.call('ZREMRANGEBYSCORE', key, 0, nowTicks - windowTicks)
        local existing = redis.call('ZCARD', key)
        if existing >= limit then
            local oldest = ''
            local oldestEntries = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
            if #oldestEntries == 2 then oldest = oldestEntries[2] end
            redis.call('EXPIRE', key, ttl)
            return { 0, existing, oldest }
        end
        local member = nowTicks .. '-' .. redis.call('INCR', key .. ':seq')
        redis.call('ZADD', key, nowTicks, member)
        local count = redis.call('ZCARD', key)
        redis.call('EXPIRE', key, ttl)
        redis.call('EXPIRE', key .. ':seq', ttl)
        return { 1, count, '' }
        """;

    public RedisRateLimitStore(RedisConnectionFactory factory, string keyPrefix, TimeProvider timeProvider)
    {
        _factory = factory ?? throw new ArgumentNullException(nameof(factory));
        _prefix = keyPrefix;
        _timeProvider = timeProvider;
    }

    public async Task<RateLimitDecision> TryIncrementAsync(string key, int limit, TimeSpan window, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        var db = await GetDatabaseAsync(ct).ConfigureAwait(false);
        var nowTicks = _timeProvider.GetUtcNow().UtcTicks;
        var fullKey = _prefix + key;

        var raw = await db.ScriptEvaluateAsync(
            IncrLuaScript,
            new RedisKey[] { fullKey },
            new RedisValue[] { nowTicks, window.Ticks, limit }).ConfigureAwait(false);

        var arr = (RedisResult[]?)raw;
        if (arr is null || arr.Length < 2)
            return new RateLimitDecision(true, 0, TimeSpan.Zero);

        var allowed = (long)arr[0]! == 1L;
        var count = (int)(long)arr[1]!;
        var retryAfter = TimeSpan.Zero;
        if (!allowed && arr.Length >= 3)
        {
            var oldestStr = (string?)arr[2];
            if (!string.IsNullOrEmpty(oldestStr) && long.TryParse(oldestStr, out var oldestTicks))
            {
                var elapsed = nowTicks - oldestTicks;
                retryAfter = TimeSpan.FromTicks(Math.Max(window.Ticks - elapsed, TimeSpan.TicksPerSecond));
            }
        }
        return new RateLimitDecision(allowed, count, retryAfter);
    }

    public async Task ResetAsync(string key, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        var db = await GetDatabaseAsync(ct).ConfigureAwait(false);
        var fullKey = _prefix + key;
        await db.KeyDeleteAsync(new RedisKey[] { fullKey, fullKey + ":seq" }).ConfigureAwait(false);
    }

    private async Task<IDatabase> GetDatabaseAsync(CancellationToken ct)
    {
        if (_connection is { IsConnected: true })
            return _connection.GetDatabase(_factory.Database);

        await _connectionLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_connection is { IsConnected: true })
                return _connection.GetDatabase(_factory.Database);

            var config = _factory.Build();
            _connection = await ConnectionMultiplexer.ConnectAsync(config).ConfigureAwait(false);
            return _connection.GetDatabase(_factory.Database);
        }
        finally
        {
            _connectionLock.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_connection is not null)
            await _connection.DisposeAsync().ConfigureAwait(false);
        _connectionLock.Dispose();
    }

    public void Dispose()
    {
        _connection?.Dispose();
        _connectionLock.Dispose();
    }
}
