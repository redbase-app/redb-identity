using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Sessions;

/// <summary>
/// Request body for <c>POST /api/internal/revoked-sids</c>.
/// <para>
/// Caller MUST provide <see cref="Sid"/> OR <see cref="Sub"/> (or both). Sub-only marks every
/// session of that subject as revoked — used for "logout everywhere" / admin <c>RevokeAll</c>.
/// </para>
/// </summary>
public sealed class RevokedSidsAddRequest
{
    /// <summary>OIDC <c>sid</c> claim of the revoked session.</summary>
    [JsonPropertyName("sid")]
    public string? Sid { get; set; }

    /// <summary>OIDC <c>sub</c> claim. When set without <see cref="Sid"/>, revokes all sessions of subject.</summary>
    [JsonPropertyName("sub")]
    public string? Sub { get; set; }

    /// <summary>Optional client_id scope. Null = applies to all clients.</summary>
    [JsonPropertyName("clientId")]
    public string? ClientId { get; set; }

    /// <summary>
    /// When the entry expires (RPs use this as TTL for their local cache). Server enforces a
    /// configurable upper bound (default 24h).
    /// </summary>
    [JsonPropertyName("expiresAt")]
    public DateTimeOffset? ExpiresAt { get; set; }
}
