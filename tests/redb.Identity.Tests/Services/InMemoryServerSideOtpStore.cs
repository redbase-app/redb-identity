using redb.Identity.Core.Mfa;

namespace redb.Identity.Tests.Services;

/// <summary>
/// In-memory <see cref="IServerSideOtpStore"/> for unit tests. Replicates the invariants
/// of <see cref="PropsServerSideOtpStore"/> (single-use, user cross-check, expiry) without a
/// real PROPS backing store.
/// </summary>
internal sealed class InMemoryServerSideOtpStore : IServerSideOtpStore
{
    private readonly Dictionary<Guid, Entry> _store = new();
    private sealed record Entry(long UserId, string Method, string Code, DateTimeOffset ExpiresAt, bool Consumed);

    public Task<OtpIssueResult> IssueAsync(long userId, string method, string destinationMasked, TimeSpan ttl, CancellationToken ct = default)
    {
        var jti = Guid.NewGuid();
        // Fixed code so tests can assert against it directly.
        var code = "123456";
        var expires = DateTimeOffset.UtcNow + ttl;
        _store[jti] = new Entry(userId, method, code, expires, false);
        return Task.FromResult(new OtpIssueResult(jti, code, destinationMasked, expires));
    }

    public Task<OtpVerifyResult> VerifyAndConsumeAsync(Guid jti, long userId, string code, CancellationToken ct = default)
    {
        if (!_store.TryGetValue(jti, out var e)) return Task.FromResult(new OtpVerifyResult(false, "not_found"));
        if (e.UserId != userId) return Task.FromResult(new OtpVerifyResult(false, "user_mismatch", e.Method));
        if (e.Consumed) return Task.FromResult(new OtpVerifyResult(false, "already_consumed", e.Method));
        if (e.ExpiresAt < DateTimeOffset.UtcNow) return Task.FromResult(new OtpVerifyResult(false, "expired", e.Method));
        if (e.Code != code.Trim()) return Task.FromResult(new OtpVerifyResult(false, "bad_code", e.Method));
        _store[jti] = e with { Consumed = true };
        return Task.FromResult(new OtpVerifyResult(true, "ok", e.Method));
    }

    /// <summary>Test helper: seeds a known <c>(jti, code)</c> pair so tests can build an MfaState.</summary>
    public Guid Seed(long userId, string method, string code)
    {
        var jti = Guid.NewGuid();
        _store[jti] = new Entry(userId, method, code, DateTimeOffset.UtcNow.AddMinutes(5), false);
        return jti;
    }
}
