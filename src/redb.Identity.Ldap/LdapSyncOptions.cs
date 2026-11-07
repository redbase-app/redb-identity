namespace redb.Identity.Ldap;

/// <summary>
/// Configuration for the LDAP directory sync route (Watch consumer).
/// Extends connection settings with sync-specific options.
/// </summary>
public sealed class LdapSyncOptions : LdapConnectionSettings
{
    /// <summary>Route identifier. Default: "ldap-sync".</summary>
    public string RouteId { get; set; } = "ldap-sync";

    // ── Search ──

    /// <summary>Base DN for user search.</summary>
    public string UserBaseDn { get; set; } = "";

    /// <summary>LDAP filter for user entries. Default: "(objectClass=inetOrgPerson)".</summary>
    public string UserFilter { get; set; } = "(objectClass=inetOrgPerson)";

    /// <summary>LDAP attributes to request.</summary>
    public string[] Attributes { get; set; } = [];

    // ── Change tracking ──

    /// <summary>Poll interval in milliseconds. Default: 60000 (1 min).</summary>
    public int PollIntervalMs { get; set; } = 60_000;

    /// <summary>Change tracking mode. Default: ModifyTimestamp.</summary>
    public string ChangeTrackingMode { get; set; } = "ModifyTimestamp";

    /// <summary>Load all entries on first poll. Default: true.</summary>
    public bool InitialLoad { get; set; } = true;

    /// <summary>Detect deleted entries. Default: true.</summary>
    public bool DetectDeletions { get; set; } = true;

    /// <summary>Full sync interval in poll cycles (for deletion detection). Default: 10.</summary>
    public int FullSyncInterval { get; set; } = 10;

    // ── Identity integration ──

    /// <summary>Provider name stored in user's ExternalProvider field. Default: "ldap-sync".</summary>
    public string ProviderName { get; set; } = "ldap-sync";

    /// <summary>
    /// Attribute map for converting LDAP entries to user profiles.
    /// Keys: "externalId", "displayName", "email", "phone", "givenName", "familyName".
    /// </summary>
    public Dictionary<string, string> AttributeMap { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Extra LDAP attributes mapped to custom claims.</summary>
    public Dictionary<string, string> AdditionalClaimsMap { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Enable group sync from memberOf attribute. Default: false.</summary>
    public bool SyncGroups { get; set; }

    /// <summary>Group mapper options (used when SyncGroups = true).</summary>
    public LdapGroupMapperOptions GroupMapperOptions { get; set; } = new();

    /// <summary>Whether to disable users when they are deleted from LDAP. Default: true.</summary>
    public bool DisableDeletedUsers { get; set; } = true;

    private static readonly HashSet<string> ValidTrackingModes = new(StringComparer.OrdinalIgnoreCase)
    {
        "ModifyTimestamp", "Usn", "Persistent"
    };

    public void Validate()
    {
        ValidateConnection();

        if (string.IsNullOrWhiteSpace(UserBaseDn))
            throw new InvalidOperationException("LdapSyncOptions.UserBaseDn is required.");

        if (PollIntervalMs <= 0)
            throw new InvalidOperationException(
                $"LdapSyncOptions.PollIntervalMs must be positive, got: {PollIntervalMs}.");

        if (!ValidTrackingModes.Contains(ChangeTrackingMode))
            throw new InvalidOperationException(
                $"LdapSyncOptions.ChangeTrackingMode '{ChangeTrackingMode}' is not valid. Use: {string.Join(", ", ValidTrackingModes)}.");
    }
}
