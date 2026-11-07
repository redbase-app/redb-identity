using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Sessions;

/// <summary>
/// One entry in the revoked-sids list returned to a polling Relying Party (RP).
/// <para>
/// At least one of <see cref="Sid"/> or <see cref="Sub"/> is set:
/// <list type="bullet">
///   <item><see cref="Sid"/> only — single OIDC session was revoked.</item>
///   <item><see cref="Sub"/> only — every session of that subject is revoked
///         (used for "logout everywhere" / admin <c>RevokeAll</c>).</item>
///   <item>Both — explicit single-session revoke that also carries the subject for forensics.</item>
/// </list>
/// </para>
/// <para>RP-side cache MUST evict entries past <see cref="ExpiresAt"/>.</para>
/// </summary>
public sealed class RevokedSidEntry
{
    /// <summary>OIDC <c>sid</c> claim of the revoked session, when known.</summary>
    [JsonPropertyName("sid")]
    public string? Sid { get; set; }

    /// <summary>OIDC <c>sub</c> claim — present for "revoke all sessions of subject" entries.</summary>
    [JsonPropertyName("sub")]
    public string? Sub { get; set; }

    /// <summary>Optional OAuth client_id this revocation applies to. Null = applies to all clients.</summary>
    [JsonPropertyName("clientId")]
    public string? ClientId { get; set; }

    /// <summary>UTC timestamp the entry was created. RPs use this as the polling cursor.</summary>
    [JsonPropertyName("revokedAt")]
    public DateTimeOffset RevokedAt { get; set; }

    /// <summary>UTC timestamp after which this entry can be evicted (typically max cookie lifetime).</summary>
    [JsonPropertyName("expiresAt")]
    public DateTimeOffset ExpiresAt { get; set; }
}
