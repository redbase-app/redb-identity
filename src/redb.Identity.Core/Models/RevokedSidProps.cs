using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// W6-0: One revocation entry in the backchannel revoked-sids list.
/// <para>
/// At least one of <see cref="Sid"/> / <see cref="Sub"/> is set:
/// <list type="bullet">
///   <item><see cref="Sid"/> only \u2014 single OIDC session was revoked.</item>
///   <item><see cref="Sub"/> only \u2014 every session of that subject is revoked
///         ("logout everywhere" / admin <c>RevokeAll</c>).</item>
///   <item>Both \u2014 explicit single-session revoke that also carries the subject.</item>
/// </list>
/// </para>
/// <para>
/// Polling Relying Parties (RPs) call <c>GET /api/internal/revoked-sids/since</c> to fetch
/// new entries; their local cache evicts past <see cref="ExpiresAt"/>. The
/// <c>identity-revoked-sids-cleanup</c> route soft-deletes rows past <see cref="ExpiresAt"/>
/// on a leader-only timer (<c>.Cluster(true)</c>).
/// </para>
/// </summary>
[RedbScheme("identity.revoked_sid")]
public class RevokedSidProps
{
    /// <summary>OIDC <c>sid</c> claim of the revoked session, or null when only <see cref="Sub"/> is set.</summary>
    public string? Sid { get; set; }

    /// <summary>OIDC <c>sub</c> claim. Set for sub-only ("revoke all sessions of subject") entries.</summary>
    public string? Sub { get; set; }

    /// <summary>Optional OAuth client_id this revocation applies to. Null = applies to all clients.</summary>
    public string? ClientId { get; set; }

    /// <summary>UTC timestamp the entry was created. RPs use this as the polling cursor.</summary>
    public DateTimeOffset RevokedAt { get; set; }

    /// <summary>UTC timestamp after which this entry can be evicted (typically max cookie lifetime).</summary>
    public DateTimeOffset ExpiresAt { get; set; }
}
