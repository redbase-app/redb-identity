using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// PROPS Props for OAuth 2.0 / OIDC token (access, refresh, id, authorization_code).
/// Base fields: key = userId (subject), date_create, date_complete = expiry, date_begin = redemption.
/// </summary>
[RedbScheme("identity.token")]
public class TokenProps
{
    /// <summary>FK → ApplicationProps object id.</summary>
    public long ApplicationObjectId { get; set; }

    /// <summary>FK → AuthorizationProps object id.</summary>
    public long AuthorizationObjectId { get; set; }

    /// <summary>"valid", "revoked", "redeemed", or "inactive".</summary>
    public string? Status { get; set; }

    /// <summary>"access_token", "refresh_token", "id_token", or "authorization_code".</summary>
    public string? Type { get; set; }

    /// <summary>Opaque reference id (for reference tokens).</summary>
    public string? ReferenceId { get; set; }

    /// <summary>
    /// Serialized token payload content.
    /// Stored in root _objects.note field (not PROPS) to avoid btree index size limits.
    /// </summary>
    [RedbIgnore]
    public string? Payload { get; set; }

    /// <summary>Extensible properties bag.</summary>
    public Dictionary<string, string>? Properties { get; set; }

    /// <summary>
    /// Subject of the actor in a delegation token exchange (RFC 8693).
    /// Stored for audit/query — the full <c>act</c> claim chain is in the token payload.
    /// </summary>
    public string? ActorSubject { get; set; }
}
