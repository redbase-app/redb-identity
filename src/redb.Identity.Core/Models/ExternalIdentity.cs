namespace redb.Identity.Core.Models;

/// <summary>
/// Federation identity linking a local user to an external provider (OIDC, LDAP, SAML).
/// Stored as nested PROPS object inside <see cref="UserProps.ExternalIdentities"/> dictionary.
/// </summary>
public class ExternalIdentity
{
    /// <summary>Subject identifier in the external system (OIDC sub, LDAP DN, SAML NameID).</summary>
    public string? Sub { get; set; }

    /// <summary>When this identity was linked to the local user.</summary>
    public DateTimeOffset LinkedAt { get; set; }
}
