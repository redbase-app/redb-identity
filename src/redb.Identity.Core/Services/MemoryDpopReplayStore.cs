using System.Collections.Concurrent;

namespace redb.Identity.Core.Services;

/// <summary>
/// In-process implementation of <see cref="IDpopReplayStore"/>. Backed by a
/// <see cref="ConcurrentDictionary{TKey,TValue}"/> with TTL-based pruning.
/// Single-instance only — see <see cref="Configuration.DpopReplayStoreOptions"/>.
/// </summary>
public sealed class MemoryDpopReplayStore : IDpopReplayStore, IDisposable
{
    private readonly TimeProvider _timeProvider;
    private readonly ConcurrentDictionary<string, long> _seen = new(StringComparer.Ordinal);
    private readonly Timer? _sweeper;

    public MemoryDpopReplayStore(TimeProvider? timeProvider = null, TimeSpan? sweepInterval = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
        var interval = sweepInterval ?? TimeSpan.FromMinutes(5);
        if (interval > TimeSpan.Zero && interval != Timeout.InfiniteTimeSpan)
        {
            _sweeper = new Timer(_ => Prune(), null, interval, interval);
        }
    }

    /// <inheritdoc />
    public Task<bool> TryReserveAsync(string jkt, string jti, TimeSpan ttl, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(jkt) || string.IsNullOrEmpty(jti))
            return Task.FromResult(false);

        var nowTicks = _timeProvider.GetUtcNow().UtcTicks;
        var expiryTicks = nowTicks + Math.Max(ttl.Ticks, TimeSpan.TicksPerSecond);
        var key = jkt + "|" + jti;

        if (_seen.TryAdd(key, expiryTicks))
            return Task.FromResult(true);

        // Existing entry: only allow re-reservation when it has expired.
        if (_seen.TryGetValue(key, out var existing) && existing <= nowTicks
            && _seen.TryUpdate(key, expiryTicks, existing))
        {
            return Task.FromResult(true);
        }

        return Task.FromResult(false);
    }

    private void Prune()
    {
        var nowTicks = _timeProvider.GetUtcNow().UtcTicks;
        foreach (var kv in _seen)
        {
            if (kv.Value <= nowTicks)
                _seen.TryRemove(kv.Key, out _);
        }
    }

    public void Dispose() => _sweeper?.Dispose();
}
