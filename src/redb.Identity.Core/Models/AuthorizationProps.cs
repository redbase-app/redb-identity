using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// PROPS Props for OAuth 2.0 authorization (grant / consent record).
/// Base fields: key = userId (subject), date_create, date_complete = expiry.
/// </summary>
[RedbScheme("identity.authorization")]
public class AuthorizationProps
{
    /// <summary>FK → ApplicationProps object id.</summary>
    public long ApplicationObjectId { get; set; }

    /// <summary>"valid", "revoked", or "redeemed".</summary>
    public string? Status { get; set; }

    /// <summary>"permanent" or "ad-hoc".</summary>
    public string? Type { get; set; }

    /// <summary>Granted scopes: ["openid", "profile", "email"].</summary>
    public string[]? Scopes { get; set; }

    /// <summary>Extensible properties bag.</summary>
    public Dictionary<string, string>? Properties { get; set; }
}
