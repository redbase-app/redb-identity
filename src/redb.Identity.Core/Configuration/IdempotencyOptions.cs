namespace redb.Identity.Core.Configuration;

/// <summary>
/// E2 — RFC-style <c>Idempotency-Key</c> support for admin/SCIM mutation endpoints.
/// <para>
/// When enabled, repeated requests carrying the same <c>Idempotency-Key</c> header (within
/// <see cref="Ttl"/>) replay the cached response body and HTTP status code instead of
/// re-executing the underlying mutation. Storage backend: redb PROPS
/// (<c>identity.idempotency_record</c>) with TTL cleanup via
/// <see cref="redb.Core.Services.IBackgroundDeletionService"/> — no Redis dependency.
/// </para>
/// <para>
/// Token issuance is auto-idempotent through the one-time <c>code</c> grant (see C11), so
/// the protocol routes do not consult this cache.
/// </para>
/// </summary>
public sealed class IdempotencyOptions
{
    /// <summary>
    /// Master switch for idempotency caching. When <c>false</c>, the
    /// <c>Idempotency-Key</c> header is ignored and every mutation executes normally.
    /// Default: <c>true</c>.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// How long a cached response is replayed for the same key. After this window the
    /// stored record is eligible for background deletion and a fresh request creates a new
    /// resource. Default: 24 hours (de-facto industry standard, e.g. Stripe).
    /// </summary>
    public TimeSpan Ttl { get; set; } = TimeSpan.FromHours(24);

    /// <summary>
    /// Maximum accepted length of the inbound <c>Idempotency-Key</c> header value. Keys
    /// longer than this limit are silently ignored (treated as if no key was supplied) so a
    /// caller cannot blow up the PROPS name index with arbitrary payload. Default: 200.
    /// </summary>
    public int MaxKeyLength { get; set; } = 200;
}
