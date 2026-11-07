using redb.Route.Redis;
using StackExchange.Redis;

namespace redb.Identity.Core.Services;

/// <summary>
/// Redis-backed <see cref="IDpopReplayStore"/>. Uses atomic <c>SET key NX EX ttl</c>
/// so the first writer wins; concurrent replays observe the existing key.
/// </summary>
internal sealed class RedisDpopReplayStore : IDpopReplayStore, IAsyncDisposable, IDisposable
{
    private readonly RedisConnectionFactory _factory;
    private readonly string _prefix;
    private readonly SemaphoreSlim _connectionLock = new(1, 1);

    private IConnectionMultiplexer? _connection;

    public RedisDpopReplayStore(RedisConnectionFactory factory, string keyPrefix)
    {
        _factory = factory ?? throw new ArgumentNullException(nameof(factory));
        _prefix = keyPrefix ?? string.Empty;
    }

    public async Task<bool> TryReserveAsync(string jkt, string jti, TimeSpan ttl, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(jkt) || string.IsNullOrEmpty(jti))
            return false;

        ct.ThrowIfCancellationRequested();
        var db = await GetDatabaseAsync(ct).ConfigureAwait(false);
        var fullKey = _prefix + jkt + ":" + jti;
        var ttlSpan = ttl <= TimeSpan.Zero ? TimeSpan.FromMinutes(5) : ttl;

        return await db.StringSetAsync(
            fullKey,
            "1",
            expiry: ttlSpan,
            when: When.NotExists).ConfigureAwait(false);
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
