using System.Collections.Concurrent;

namespace redb.Identity.Core.Services;

/// <summary>
/// C1 — Per-node sliding-window counter using <see cref="ConcurrentDictionary{TKey,TValue}"/>
/// and a per-key lock around a <see cref="Queue{T}"/> of hit timestamps.
/// </summary>
/// <remarks>
/// <para>
/// Default backend for <see cref="IRateLimitStore"/>. Counters live in process memory and
/// reset on restart. In a multi-node cluster the effective ceiling is <c>N × limit</c>;
/// this is acceptable for online brute-force defence (each node still slows attackers and
/// correlates per-IP). For a true global limit, switch
/// <see cref="Configuration.RateLimitOptions.Backend"/> to <c>"redis"</c>.
/// </para>
/// <para>
/// Memory bounded by <c>unique-keys × limit × 16 bytes</c>. A background sweep removes
/// buckets that have been empty for at least <c>2 × longestWindow</c> (hard-coded 1 hour
/// upper bound) so unbounded distinct-IP traffic eventually gets reaped.
/// </para>
/// </remarks>
internal sealed class InMemoryRateLimitStore : IRateLimitStore, IDisposable
{
    private readonly ConcurrentDictionary<string, BucketState> _buckets = new();
    private readonly TimeProvider _timeProvider;
    private readonly Timer? _gcTimer;
    private static readonly TimeSpan GcInterval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan StaleAfter = TimeSpan.FromHours(1);

    public InMemoryRateLimitStore() : this(TimeProvider.System) { }

    public InMemoryRateLimitStore(TimeProvider timeProvider)
    {
        _timeProvider = timeProvider;

        // The background sweep is only useful with the real wall-clock; under a test /
        // fake time provider it would never tick and would also leak Timer instances
        // across many test fixtures. Tests can call PurgeStale() directly.
        if (!ReferenceEquals(timeProvider, TimeProvider.System))
        {
            _gcTimer = null;
            return;
        }

        _gcTimer = new Timer(_ => PurgeStale(), null, GcInterval, GcInterval);
    }

    public Task<RateLimitDecision> TryIncrementAsync(string key, int limit, TimeSpan window, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        var state = _buckets.GetOrAdd(key, _ => new BucketState());
        var nowTicks = _timeProvider.GetUtcNow().UtcTicks;
        var windowStartTicks = nowTicks - window.Ticks;

        lock (state.SyncRoot)
        {
            // Drop hits older than the window.
            while (state.Hits.Count > 0 && state.Hits.Peek() < windowStartTicks)
                state.Hits.Dequeue();

            if (state.Hits.Count >= limit)
            {
                var oldest = state.Hits.Peek();
                var retryAfterTicks = window.Ticks - (nowTicks - oldest);
                if (retryAfterTicks < TimeSpan.TicksPerSecond)
                    retryAfterTicks = TimeSpan.TicksPerSecond;
                state.LastTouchedTicks = nowTicks;
                return Task.FromResult(new RateLimitDecision(false, state.Hits.Count, TimeSpan.FromTicks(retryAfterTicks)));
            }

            state.Hits.Enqueue(nowTicks);
            state.LastTouchedTicks = nowTicks;
            return Task.FromResult(new RateLimitDecision(true, state.Hits.Count, TimeSpan.Zero));
        }
    }

    public Task ResetAsync(string key, CancellationToken ct = default)
    {
        if (_buckets.TryGetValue(key, out var state))
        {
            lock (state.SyncRoot)
            {
                state.Hits.Clear();
                state.LastTouchedTicks = _timeProvider.GetUtcNow().UtcTicks;
            }
        }
        return Task.CompletedTask;
    }

    /// <summary>Removes buckets untouched for <see cref="StaleAfter"/>. Exposed for tests.</summary>
    internal void PurgeStale()
    {
        var thresholdTicks = _timeProvider.GetUtcNow().UtcTicks - StaleAfter.Ticks;
        foreach (var (key, state) in _buckets)
        {
            lock (state.SyncRoot)
            {
                if (state.LastTouchedTicks < thresholdTicks && state.Hits.Count == 0)
                    _buckets.TryRemove(key, out _);
            }
        }
    }

    public void Dispose() => _gcTimer?.Dispose();

    private sealed class BucketState
    {
        public readonly object SyncRoot = new();
        public readonly Queue<long> Hits = new();
        public long LastTouchedTicks;
    }
}
