namespace redb.Identity.Core.Services;

/// <summary>
/// One-time-use nonce store for federation state blobs (C6).
/// Each issued state carries a unique <c>jti</c>; the callback path consumes it
/// exactly once. Implementations MUST be safe for concurrent calls and MUST
/// auto-expire entries after their TTL to bound memory.
/// </summary>
public interface IFederationStateNonceStore
{
    /// <summary>
    /// Records the <paramref name="jti"/> as consumed and returns <c>true</c> iff
    /// it was previously unseen. Subsequent calls with the same <paramref name="jti"/>
    /// (within <paramref name="ttl"/>) MUST return <c>false</c>.
    /// </summary>
    Task<bool> TryConsumeAsync(string jti, TimeSpan ttl, CancellationToken ct = default);
}
