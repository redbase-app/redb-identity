using redb.Identity.Core.Services;
using redb.Route.Ldap;

namespace redb.Identity.Ldap;

/// <summary>
/// Maps LDAP entry attributes to <see cref="ExternalAuthResult"/> fields
/// using the attribute map from <see cref="LdapProviderOptions"/>.
/// </summary>
public sealed class LdapAttributeMapper
{
    private readonly LdapProviderOptions _options;

    public LdapAttributeMapper(LdapProviderOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <summary>
    /// Extracts the mapped field value from an LDAP entry.
    /// Returns null if the field is not mapped or the attribute is missing.
    /// </summary>
    public string? GetField(LdapEntry entry, string fieldName)
    {
        if (!_options.AttributeMap.TryGetValue(fieldName, out var ldapAttr))
            return null;

        return entry.GetString(ldapAttr);
    }

    /// <summary>
    /// Builds the ExternalAuthResult from an LDAP entry using the configured attribute map.
    /// </summary>
    public ExternalAuthResult MapToResult(LdapEntry entry)
    {
        var externalId = GetField(entry, "externalId") ?? entry.Dn;
        var displayName = GetField(entry, "displayName");
        var email = GetField(entry, "email");
        var phone = GetField(entry, "phone");
        var givenName = GetField(entry, "givenName");
        var familyName = GetField(entry, "familyName");

        Dictionary<string, string>? additionalClaims = null;

        if (_options.AdditionalClaimsMap.Count > 0)
        {
            additionalClaims = new Dictionary<string, string>();
            foreach (var (claimName, ldapAttr) in _options.AdditionalClaimsMap)
            {
                var value = entry.GetString(ldapAttr);
                if (value != null)
                    additionalClaims[claimName] = value;
            }

            if (additionalClaims.Count == 0)
                additionalClaims = null;
        }

        return ExternalAuthResult.Success(
            externalId: externalId,
            displayName: displayName,
            email: email,
            phone: phone,
            givenName: givenName,
            familyName: familyName,
            additionalClaims: additionalClaims);
    }

    /// <summary>
    /// Returns the list of LDAP attribute names needed for the search request.
    /// Includes both field attributes and additional claims attributes.
    /// </summary>
    public string[] GetRequestedAttributes()
    {
        var attrs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var ldapAttr in _options.AttributeMap.Values)
            attrs.Add(ldapAttr);

        foreach (var ldapAttr in _options.AdditionalClaimsMap.Values)
            attrs.Add(ldapAttr);

        return attrs.ToArray();
    }
}
