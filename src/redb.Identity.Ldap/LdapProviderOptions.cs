namespace redb.Identity.Ldap;

/// <summary>
/// Configuration for LDAP external user provider.
/// </summary>
public sealed class LdapProviderOptions : LdapConnectionSettings
{
    /// <summary>Provider name reported to LoginService. Default: "ldap".</summary>
    public string ProviderName { get; set; } = "ldap";

    /// <summary>Priority in the external provider chain (lower = tried first). Default: 100.</summary>
    public int Priority { get; set; } = 100;

    // ── User search ──

    /// <summary>Base DN for user search, e.g. "ou=users,dc=example,dc=com".</summary>
    public string UserBaseDn { get; set; } = "";

    /// <summary>
    /// LDAP search filter template. Use <c>{0}</c> for username substitution.
    /// Default: "(uid={0})" for OpenLDAP. For AD use "(&amp;(objectClass=user)(sAMAccountName={0}))".
    /// </summary>
    public string UserFilter { get; set; } = "(uid={0})";

    /// <summary>Search scope. Default: subtree.</summary>
    public LdapSearchScopeOption SearchScope { get; set; } = LdapSearchScopeOption.Subtree;

    // ── Attribute mapping ──

    /// <summary>
    /// Map of identity fields to LDAP attribute names.
    /// Keys: "externalId", "displayName", "email", "phone", "givenName", "familyName".
    /// Unmapped fields are not populated.
    /// </summary>
    public Dictionary<string, string> AttributeMap { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Extra LDAP attributes mapped to AdditionalClaims.
    /// Key = claim name, Value = LDAP attribute name.
    /// Example: { "department" = "departmentNumber", "title" = "title" }.
    /// </summary>
    public Dictionary<string, string> AdditionalClaimsMap { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    // ── Domain routing ──

    /// <summary>
    /// Accepted domain hints (e.g. "corp.example.com", "CORP").
    /// When non-empty, only usernames with a matching domain hint (user@domain or DOMAIN\user) are accepted.
    /// Usernames without a domain hint are passed through as-is.
    /// Empty array = accept all usernames (no domain filtering).
    /// </summary>
    public string[] Domains { get; set; } = [];

    /// <summary>Whether to check userAccountControl flags (AD only). Default: false.</summary>
    public bool CheckAccountStatus { get; set; }

    /// <summary>
    /// Apply a named preset (overwrites AttributeMap and UserFilter).
    /// </summary>
    public void ApplyPreset(LdapPreset preset)
    {
        var (filter, map) = preset switch
        {
            LdapPreset.OpenLDAP => (
                "(uid={0})",
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["externalId"] = "uid",
                    ["displayName"] = "cn",
                    ["email"] = "mail",
                    ["phone"] = "telephoneNumber",
                    ["givenName"] = "givenName",
                    ["familyName"] = "sn"
                }),
            LdapPreset.ActiveDirectory => (
                "(&(objectClass=user)(sAMAccountName={0}))",
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["externalId"] = "sAMAccountName",
                    ["displayName"] = "displayName",
                    ["email"] = "mail",
                    ["phone"] = "telephoneNumber",
                    ["givenName"] = "givenName",
                    ["familyName"] = "sn"
                }),
            _ => throw new ArgumentOutOfRangeException(nameof(preset))
        };

        UserFilter = filter;
        AttributeMap = map;

        if (preset == LdapPreset.ActiveDirectory)
            CheckAccountStatus = true;
    }

    /// <summary>
    /// Restores case-insensitive comparers on dictionaries after IConfiguration.Bind().
    /// </summary>
    public void NormalizeAfterBind()
    {
        if (AttributeMap.Comparer != StringComparer.OrdinalIgnoreCase)
            AttributeMap = new Dictionary<string, string>(AttributeMap, StringComparer.OrdinalIgnoreCase);
        if (AdditionalClaimsMap.Comparer != StringComparer.OrdinalIgnoreCase)
            AdditionalClaimsMap = new Dictionary<string, string>(AdditionalClaimsMap, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Validates the options and throws on misconfiguration.
    /// </summary>
    public void Validate()
    {
        ValidateConnection();

        if (string.IsNullOrWhiteSpace(UserBaseDn))
            throw new InvalidOperationException("LdapProviderOptions.UserBaseDn is required.");

        if (string.IsNullOrWhiteSpace(UserFilter) || !UserFilter.Contains("{0}"))
            throw new InvalidOperationException("LdapProviderOptions.UserFilter must contain '{0}' placeholder.");
    }
}

/// <summary>Known LDAP directory presets.</summary>
public enum LdapPreset
{
    /// <summary>OpenLDAP / 389DS defaults (uid, cn, mail, etc.).</summary>
    OpenLDAP,

    /// <summary>Active Directory defaults (sAMAccountName, displayName, mail, etc.).</summary>
    ActiveDirectory
}

/// <summary>LDAP search scope.</summary>
public enum LdapSearchScopeOption
{
    /// <summary>Search only the base DN entry.</summary>
    Base,

    /// <summary>Search one level below the base DN.</summary>
    OneLevel,

    /// <summary>Search the entire subtree below the base DN.</summary>
    Subtree
}
