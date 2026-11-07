namespace redb.Identity.Core.Services;

/// <summary>
/// C1 — Outcome of a rate-limit check / increment.
/// </summary>
/// <param name="Allowed"><c>true</c> if the call may proceed; <c>false</c> if it should be rejected with HTTP 429.</param>
/// <param name="Count">The bucket count AFTER the increment (or the current count when denied without incrementing).</param>
/// <param name="RetryAfter">When <see cref="Allowed"/> is <c>false</c>, hint to the client for the <c>Retry-After</c> header.</param>
public readonly record struct RateLimitDecision(bool Allowed, int Count, TimeSpan RetryAfter);

/// <summary>
/// C1 — Sliding-window counter store used by the rate-limit processors. Implementations
/// must be safe for concurrent use across many threads. Default impl: in-memory per-node;
/// optional impl: Redis (cluster-global). Selected via
/// <see cref="Configuration.RateLimitOptions.Backend"/>.
/// </summary>
public interface IRateLimitStore
{
    /// <summary>
    /// Records a hit on <paramref name="key"/> within a sliding window of <paramref name="window"/>
    /// length and returns whether the bucket is still under <paramref name="limit"/>.
    /// </summary>
    /// <remarks>
    /// MUST behave atomically: concurrent callers either all see the increment or none do.
    /// When <see cref="RateLimitDecision.Allowed"/> is <c>false</c>, implementations MAY
    /// still record the hit (extends penalty) — caller treats both modes uniformly via 429.
    /// </remarks>
    Task<RateLimitDecision> TryIncrementAsync(string key, int limit, TimeSpan window, CancellationToken ct = default);

    /// <summary>
    /// Forcibly resets the counter for <paramref name="key"/>. Used when an authentication
    /// attempt SUCCEEDS so a single legitimate sign-in clears the failure tally.
    /// </summary>
    Task ResetAsync(string key, CancellationToken ct = default);
}
