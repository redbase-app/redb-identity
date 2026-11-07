using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// E2 — PROPS record for cached responses of <c>Idempotency-Key</c>-bearing requests.
/// <para>
/// Lookup is keyed by the indexed <c>name</c> column (composite
/// <c>idem:{scope}:{operation}:{caller}:{key}</c>). The TTL is encoded as the standard
/// <c>date_complete</c> field so <see cref="redb.Core.Services.IBackgroundDeletionService"/>
/// can reap expired entries with the same machinery used for token cleanup — no per-record
/// lookup is needed at request time, the cache simply respects <c>date_complete</c>.
/// </para>
/// </summary>
[RedbScheme("identity.idempotency_record")]
public class IdempotencyRecordProps
{
    /// <summary>HTTP method of the original request, e.g. <c>POST</c> / <c>PUT</c>. Audit-only.</summary>
    public string? Method { get; set; }

    /// <summary>
    /// Logical scope this record belongs to (route id of the direct-vm route that produced
    /// the response, e.g. <c>identity-manage-apps</c>). Used in the composite <c>name</c>.
    /// </summary>
    public string? Scope { get; set; }

    /// <summary>
    /// Operation header value of the original request, e.g. <c>create</c> / <c>update</c>.
    /// Distinguishes different operations under the same scope so two unrelated calls that
    /// happen to share an <c>Idempotency-Key</c> never alias each other.
    /// </summary>
    public string? Operation { get; set; }

    /// <summary>
    /// Sub-claim of the caller (or <c>"anon"</c> when no authenticated principal is on the
    /// outer exchange). Idempotency is per-caller by design: different callers using the
    /// same key produce independent records, so a client cannot be served someone else's
    /// cached response.
    /// </summary>
    public string? CallerSubject { get; set; }

    /// <summary>The verbatim <c>Idempotency-Key</c> header value (defensive equality check).</summary>
    public string? IdempotencyKey { get; set; }

    /// <summary>HTTP status code captured for replay (e.g. 200, 201, 204).</summary>
    public int StatusCode { get; set; }

    /// <summary>
    /// JSON-serialized response body captured at completion. May be <c>null</c> when the
    /// original response had no body (e.g. 204 No Content). Stored verbatim — replay
    /// deserializes it back to a <see cref="System.Text.Json.JsonElement"/> so the HTTP
    /// serializer round-trips an identical wire payload.
    /// </summary>
    public string? ResponseBody { get; set; }
}
