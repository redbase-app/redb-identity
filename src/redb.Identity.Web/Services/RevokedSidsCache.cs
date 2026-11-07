using System.Collections.Concurrent;
using redb.Identity.Contracts.Sessions;

namespace redb.Identity.Web.Services;

/// <summary>
/// W6-0 — local cache of backchannel-revoked OIDC sessions, sourced from the cluster-wide
/// <c>/api/v1/identity/revoked-sids</c> PROPS store via periodic polling
/// (<see cref="RevokedSidsPollHostedService"/>). Replaces the previous single-instance
/// whitelist (<c>InMemorySidIndex</c>) so back-channel logout works across multiple
/// Web BFF replicas.
/// </summary>
public interface IRevokedSidsCache
{
    /// <summary>
    /// True iff the supplied <paramref name="sid"/> or <paramref name="sub"/> is
    /// currently blacklisted and not yet expired.
    /// </summary>
    bool IsRevoked(string? sid, string? sub);

    /// <summary>Merge a batch of revocations into the cache (idempotent).</summary>
    void Apply(IEnumerable<RevokedSidEntry> entries);

    /// <summary>Cursor of the most recent entry observed; null until the first successful poll.</summary>
    DateTimeOffset? Cursor { get; }

    /// <summary>Update the cursor for the next poll.</summary>
    void SetCursor(DateTimeOffset cursor);
}

/// <summary>
/// Thread-safe in-memory implementation of <see cref="IRevokedSidsCache"/>. Entries
/// are pruned opportunistically on every <see cref="Apply"/> call so memory stays
/// bounded by the active retention window even on hosts that receive no traffic.
/// </summary>
public sealed class RevokedSidsCache : IRevokedSidsCache
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _bySid = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _bySub = new(StringComparer.Ordinal);
    private readonly TimeProvider _time;
    private long _cursorTicks; // DateTimeOffset.UtcTicks; 0 = no cursor yet.

    public RevokedSidsCache() : this(TimeProvider.System) { }

    public RevokedSidsCache(TimeProvider time)
    {
        _time = time ?? throw new ArgumentNullException(nameof(time));
    }

    public DateTimeOffset? Cursor
    {
        get
        {
            var ticks = Interlocked.Read(ref _cursorTicks);
            return ticks == 0 ? null : new DateTimeOffset(ticks, TimeSpan.Zero);
        }
    }

    public void SetCursor(DateTimeOffset cursor)
    {
        var ticks = cursor.UtcTicks;
        // Monotonic — never go backwards (idempotent against out-of-order polls).
        long current;
        do
        {
            current = Interlocked.Read(ref _cursorTicks);
            if (ticks <= current) return;
        }
        while (Interlocked.CompareExchange(ref _cursorTicks, ticks, current) != current);
    }

    public bool IsRevoked(string? sid, string? sub)
    {
        var now = _time.GetUtcNow();
        if (!string.IsNullOrEmpty(sid) && _bySid.TryGetValue(sid, out var expSid) && now < expSid)
            return true;
        if (!string.IsNullOrEmpty(sub) && _bySub.TryGetValue(sub, out var expSub) && now < expSub)
            return true;
        return false;
    }

    public void Apply(IEnumerable<RevokedSidEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        var now = _time.GetUtcNow();
        foreach (var e in entries)
        {
            if (e.ExpiresAt <= now) continue;

            if (!string.IsNullOrEmpty(e.Sid))
            {
                _bySid.AddOrUpdate(e.Sid, e.ExpiresAt,
                    (_, prev) => prev > e.ExpiresAt ? prev : e.ExpiresAt);
            }
            // Sid-only and sub-only entries both index by sub when present so a
            // "logout everywhere" entry (sid=null,sub=...) is fully recorded.
            if (!string.IsNullOrEmpty(e.Sub) && string.IsNullOrEmpty(e.Sid))
            {
                _bySub.AddOrUpdate(e.Sub, e.ExpiresAt,
                    (_, prev) => prev > e.ExpiresAt ? prev : e.ExpiresAt);
            }
        }

        Prune(now);
    }

    private void Prune(DateTimeOffset now)
    {
        foreach (var kv in _bySid)
            if (kv.Value <= now) _bySid.TryRemove(kv.Key, out _);
        foreach (var kv in _bySub)
            if (kv.Value <= now) _bySub.TryRemove(kv.Key, out _);
    }
}
