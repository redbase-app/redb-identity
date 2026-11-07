namespace redb.Identity.Core.Configuration;

/// <summary>
/// C1 — Configuration for per-IP / per-(IP+username) rate limiting that sits in front of
/// <c>/connect/token</c>, <c>/login</c>, <c>/mfa/verify</c>, <c>/mfa/recovery</c> and
/// <c>/mfa/methods</c> routes.
/// </summary>
/// <remarks>
/// <para>
/// The per-IP limit drops distributed brute-force attempts pooled across many usernames; the
/// per-(IP+username) failure counter blocks credential-stuffing against a single account from
/// one source. They run orthogonally to the per-account lockout enforced inside
/// <see cref="Services.MfaService"/> (B5/B6).
/// </para>
/// <para>
/// <b>In-memory backend (default).</b> A <c>ConcurrentDictionary</c>-backed sliding-window
/// counter PER NODE — across an N-node cluster the effective ceiling is <c>N × limit</c>
/// (acceptable trade-off for online brute-force; matches NGINX/Envoy node-local limits).
/// </para>
/// <para>
/// <b>Redis backend (opt-in).</b> Sliding window via a sorted set (<c>ZADD/ZREMRANGEBYSCORE/
/// ZCARD/EXPIRE</c>) executed atomically — gives a true global limit across the cluster but
/// adds one round-trip per gated request.
/// </para>
/// </remarks>
public sealed class RateLimitOptions
{
    /// <summary>Master switch. <c>false</c> = no rate-limit processors are wired into routes.</summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Per-IP requests-per-minute ceiling. Bucket = client IP (after C2 trust resolution).
    /// Applies to <c>/login</c> and <c>/connect/token</c>. Default: 30.
    /// </summary>
    public int PerIpPerMinute { get; set; } = 30;

    /// <summary>
    /// Per-(IP+username) failure ceiling within <see cref="PerIpUsernameWindow"/>.
    /// Counts every login / MFA / token failure tied to a particular (IP, username) pair.
    /// Default: 5.
    /// </summary>
    public int PerIpUsernameFailures { get; set; } = 5;

    /// <summary>Window for the per-(IP+username) failure counter. Default: 15 minutes.</summary>
    public TimeSpan PerIpUsernameWindow { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Value sent as the <c>Retry-After</c> header on 429 responses when the store cannot
    /// compute a precise hint. Default: 60 (seconds).
    /// </summary>
    public int DefaultRetryAfterSeconds { get; set; } = 60;

    /// <summary>
    /// Backing store identifier. <c>"memory"</c> (default) keeps counters per node;
    /// <c>"redis"</c> requires <see cref="RedisConnectionString"/> and gives a global limit.
    /// </summary>
    public string Backend { get; set; } = "memory";

    /// <summary>
    /// StackExchange.Redis connection string used when <see cref="Backend"/> is <c>"redis"</c>.
    /// Example: <c>localhost:6379</c>. Ignored otherwise.
    /// </summary>
    public string? RedisConnectionString { get; set; }

    /// <summary>
    /// Optional prefix applied to Redis keys to scope counters per environment / tenant.
    /// Default: <c>redb:identity:rl:</c>.
    /// </summary>
    public string RedisKeyPrefix { get; set; } = "redb:identity:rl:";
}
