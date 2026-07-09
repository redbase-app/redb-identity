using System.Collections.Concurrent;

namespace redb.Identity.Core.Services;

/// <summary>
/// Single-process implementation of <see cref="IFederationStateNonceStore"/>.
/// Records consumed <c>jti</c> values with their absolute expiry and prunes
/// expired entries on each write. Suitable for single-instance Identity hosts;
/// use <see cref="RedisFederationStateNonceStore"/> for multi-node clusters.
/// </summary>
public sealed class InMemoryFederationStateNonceStore : IFederationStateNonceStore
{
    private readonly TimeProvider _timeProvider;
    private readonly ConcurrentDictionary<string, long> _seen = new(StringComparer.Ordinal);

    public InMemoryFederationStateNonceStore(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public Task<bool> TryConsumeAsync(string jti, TimeSpan ttl, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(jti))
            return Task.FromResult(false);

        var nowTicks = _timeProvider.GetUtcNow().UtcTicks;
        var expiryTicks = nowTicks + Math.Max(ttl.Ticks, TimeSpan.TicksPerSecond);

        // Opportunistic GC — small + bounded; runs every consume.
        Prune(nowTicks);

        var added = _seen.TryAdd(jti, expiryTicks);
        if (added)
            return Task.FromResult(true);

        // Already seen — only allow re-add if previous entry has expired.
        if (_seen.TryGetValue(jti, out var existing) && existing <= nowTicks)
        {
            if (_seen.TryUpdate(jti, expiryTicks, existing))
                return Task.FromResult(true);
        }

        return Task.FromResult(false);
    }

    private void Prune(long nowTicks)
    {
        foreach (var kv in _seen)
        {
            if (kv.Value <= nowTicks)
                _seen.TryRemove(kv.Key, out _);
        }
    }
}
