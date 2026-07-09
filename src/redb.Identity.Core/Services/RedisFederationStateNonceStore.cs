using redb.Route.Redis;
using StackExchange.Redis;

namespace redb.Identity.Core.Services;

/// <summary>
/// Redis-backed implementation of <see cref="IFederationStateNonceStore"/>.
/// Uses a per-jti string key with NX semantics so the first call wins atomically;
/// the key is set with the requested TTL so expired jti values can be replayed
/// only after the original state would itself have expired (consistent with
/// <see cref="Configuration.FederationStateOptions.StateMaxAge"/>).
/// </summary>
internal sealed class RedisFederationStateNonceStore : IFederationStateNonceStore, IAsyncDisposable, IDisposable
{
    private readonly RedisConnectionFactory _factory;
    private readonly string _prefix;
    private readonly SemaphoreSlim _connectionLock = new(1, 1);

    private IConnectionMultiplexer? _connection;

    public RedisFederationStateNonceStore(RedisConnectionFactory factory, string keyPrefix)
    {
        _factory = factory ?? throw new ArgumentNullException(nameof(factory));
        _prefix = keyPrefix ?? string.Empty;
    }

    public async Task<bool> TryConsumeAsync(string jti, TimeSpan ttl, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(jti))
            return false;

        ct.ThrowIfCancellationRequested();
        var db = await GetDatabaseAsync(ct).ConfigureAwait(false);
        var fullKey = _prefix + jti;
        var ttlSpan = ttl <= TimeSpan.Zero ? TimeSpan.FromMinutes(5) : ttl;

        // Atomic SETNX with TTL — first writer wins; everyone else gets false.
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
