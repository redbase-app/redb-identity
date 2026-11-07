namespace redb.Identity.Contracts.Users;

/// <summary>
/// DTO representing a federation identity link to an external provider.
/// </summary>
public class ExternalIdentityDto
{
    /// <summary>Subject identifier in the external system (OIDC sub, LDAP DN, SAML NameID).</summary>
    public string? Sub { get; set; }

    /// <summary>When this identity was linked to the local user.</summary>
    public DateTimeOffset LinkedAt { get; set; }
}
