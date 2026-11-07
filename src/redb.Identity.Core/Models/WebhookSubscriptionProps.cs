using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// W1 — outbound webhook subscription. One row per HTTP endpoint that
/// receives identity events as POST bodies, signed with HMAC-SHA256.
///
/// <para>
/// Delivery semantics:
///   * Fire-and-forget from the originating mutation's perspective:
///     <c>WebhookDeliveryRouteConsumer</c> picks events off a
///     <c>WireTap</c> of the identity-events route and dispatches them
///     async, so a slow webhook receiver never back-pressures the
///     token endpoint or admin API.
///   * Per-subscription exponential backoff with retry limit. Failures
///     after retries are logged + audited as <c>WebhookDeliveryFailed</c>
///     so operators can wire alerting without leaving the audit log.
/// </para>
///
/// <para>
/// Filtering:
///   * <see cref="EventTypeFilter"/> = "*" — receive every event.
///   * Comma-separated list of CamelCase IDs from
///     <c>IdentityAuditEventIds</c> (e.g. "UserCreated,UserDeleted").
///   * Prefix <c>cat:</c> matches by category instead — e.g.
///     "cat:admin,cat:authentication" delivers every admin + auth event.
/// </para>
///
/// <para>
/// Signing:
///   * Body is canonical JSON of the IdentityEvent envelope.
///   * Header <c>X-RedbIdentity-Signature</c> = <c>sha256=&lt;hex&gt;</c> of
///     <c>HMAC-SHA256(secret, body)</c>. GitHub-style — covers raw body
///     bytes only, so receivers verify with the standard HMAC-SHA256
///     recipe without canonical-payload-recomposition pitfalls.
///   * Header <c>X-RedbIdentity-Timestamp</c> = ISO-8601 UTC.
///   * Header <c>X-RedbIdentity-Delivery</c> = per-attempt GUID
///     (idempotency key the receiver can dedupe on).
///   * Header <c>X-RedbIdentity-EventType</c> = canonical event id.
/// Receivers verify by recomputing HMAC over <c>timestamp + "." + body</c>
/// using the shared secret. Reject the signature window beyond ±5min to
/// dampen replay; the timestamp + delivery id make replay detection
/// trivial.
/// </para>
/// </summary>
[RedbScheme("identity.webhook_subscription")]
public class WebhookSubscriptionProps
{
    /// <summary>Operator-facing label rendered in the admin UI.</summary>
    public string? DisplayName { get; set; }

    public string? Description { get; set; }

    /// <summary>
    /// Absolute HTTP(S) URL the event is POSTed to. Validated at create
    /// time — wildcards and fragments are rejected per common-sense
    /// webhook security.
    /// </summary>
    public string Url { get; set; } = "";

    /// <summary>
    /// Filter expression — "*" (everything), comma-separated event ids,
    /// or "cat:&lt;category&gt;" tokens (also comma-separable). Defaults
    /// to "*" so a new subscription works without a follow-up edit.
    /// </summary>
    public string EventTypeFilter { get; set; } = "*";

    /// <summary>
    /// HMAC-SHA256 secret. Generated server-side on create (returned
    /// once in the response) and rotated through the secret-rotate
    /// endpoint. Receiver verifies signatures with this value.
    /// </summary>
    public string HmacSecret { get; set; } = "";

    /// <summary>Master enable switch — disabled subscriptions are skipped.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Per-attempt timeout in milliseconds. Default 5000.</summary>
    public int TimeoutMs { get; set; } = 5000;

    /// <summary>
    /// Max delivery attempts (including the first). Exponential backoff
    /// between retries: base * (2 ^ attempt). Default 3.
    /// </summary>
    public int MaxAttempts { get; set; } = 3;

    /// <summary>Backoff base in milliseconds. Default 500.</summary>
    public int RetryBackoffMs { get; set; } = 500;

    /// <summary>
    /// Extra HTTP headers attached to every delivery (e.g. an
    /// operator-managed shared auth header). Reserved redb-internal
    /// headers (`X-RedbIdentity-*`) override any clash.
    /// </summary>
    public Dictionary<string, string>? ExtraHeaders { get; set; }

    /// <summary>
    /// Optional self-rolled concurrency token surfaced on update so a
    /// stale admin tab can't silently overwrite a fresher mutation.
    /// </summary>
    public string? ConcurrencyToken { get; set; }
}
