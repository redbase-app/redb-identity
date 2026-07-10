using FluentAssertions;
using redb.Identity.Ldap;
using redb.Route.Ldap;
using Xunit;

namespace redb.Identity.Tests.Ldap;

/// <summary>
/// Unit tests for <see cref="LdapAttributeMapper"/> and <see cref="LdapProviderOptions"/>.
/// </summary>
public class LdapAttributeMapperTests
{
    // ── Presets ──

    [Fact]
    public void OpenLdapPreset_SetsCorrectFilterAndAttributeMap()
    {
        var options = new LdapProviderOptions { UserBaseDn = "dc=test" };
        options.ApplyPreset(LdapPreset.OpenLDAP);

        options.UserFilter.Should().Be("(uid={0})");
        options.AttributeMap.Should().ContainKey("externalId").WhoseValue.Should().Be("uid");
        options.AttributeMap.Should().ContainKey("displayName").WhoseValue.Should().Be("cn");
        options.AttributeMap.Should().ContainKey("email").WhoseValue.Should().Be("mail");
        options.AttributeMap.Should().ContainKey("phone").WhoseValue.Should().Be("telephoneNumber");
        options.AttributeMap.Should().ContainKey("givenName").WhoseValue.Should().Be("givenName");
        options.AttributeMap.Should().ContainKey("familyName").WhoseValue.Should().Be("sn");
    }

    [Fact]
    public void ActiveDirectoryPreset_SetsCorrectFilterAndAttributeMap()
    {
        var options = new LdapProviderOptions { UserBaseDn = "dc=test" };
        options.ApplyPreset(LdapPreset.ActiveDirectory);

        options.UserFilter.Should().Contain("sAMAccountName={0}");
        options.UserFilter.Should().Contain("objectClass=user");
        options.AttributeMap.Should().ContainKey("externalId").WhoseValue.Should().Be("sAMAccountName");
        options.AttributeMap.Should().ContainKey("displayName").WhoseValue.Should().Be("displayName");
        options.AttributeMap.Should().ContainKey("email").WhoseValue.Should().Be("mail");
    }

    // ── Mapper: MapToResult ──

    [Fact]
    public void MapToResult_MapsAllFieldsFromLdapEntry()
    {
        var options = new LdapProviderOptions { UserBaseDn = "dc=test" };
        options.ApplyPreset(LdapPreset.OpenLDAP);
        var mapper = new LdapAttributeMapper(options);

        var entry = new LdapEntry
        {
            Dn = "uid=alice,ou=users,dc=test",
            Attributes =
            {
                ["uid"] = "alice",
                ["cn"] = "Alice Wonderland",
                ["mail"] = "alice@example.com",
                ["telephoneNumber"] = "+1234567890",
                ["givenName"] = "Alice",
                ["sn"] = "Wonderland"
            }
        };

        var result = mapper.MapToResult(entry);

        result.Succeeded.Should().BeTrue();
        result.ExternalId.Should().Be("alice");
        result.DisplayName.Should().Be("Alice Wonderland");
        result.Email.Should().Be("alice@example.com");
        result.Phone.Should().Be("+1234567890");
        result.GivenName.Should().Be("Alice");
        result.FamilyName.Should().Be("Wonderland");
    }

    [Fact]
    public void MapToResult_MissingAttributes_AreNull()
    {
        var options = new LdapProviderOptions { UserBaseDn = "dc=test" };
        options.ApplyPreset(LdapPreset.OpenLDAP);
        var mapper = new LdapAttributeMapper(options);

        var entry = new LdapEntry
        {
            Dn = "uid=bob,ou=users,dc=test",
            Attributes = { ["uid"] = "bob" }
        };

        var result = mapper.MapToResult(entry);

        result.Succeeded.Should().BeTrue();
        result.ExternalId.Should().Be("bob");
        result.DisplayName.Should().BeNull();
        result.Email.Should().BeNull();
        result.Phone.Should().BeNull();
    }

    [Fact]
    public void MapToResult_FallsBackToDn_WhenExternalIdNotMapped()
    {
        var options = new LdapProviderOptions
        {
            UserBaseDn = "dc=test",
            AttributeMap = new Dictionary<string, string> { ["displayName"] = "cn" }
        };
        var mapper = new LdapAttributeMapper(options);

        var entry = new LdapEntry
        {
            Dn = "uid=noid,ou=users,dc=test",
            Attributes = { ["cn"] = "No Id User" }
        };

        var result = mapper.MapToResult(entry);

        result.ExternalId.Should().Be("uid=noid,ou=users,dc=test");
        result.DisplayName.Should().Be("No Id User");
    }

    [Fact]
    public void MapToResult_MapsAdditionalClaims()
    {
        var options = new LdapProviderOptions
        {
            UserBaseDn = "dc=test",
            AdditionalClaimsMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["department"] = "departmentNumber",
                ["title"] = "title"
            }
        };
        options.ApplyPreset(LdapPreset.OpenLDAP);
        var mapper = new LdapAttributeMapper(options);

        var entry = new LdapEntry
        {
            Dn = "uid=alice,ou=users,dc=test",
            Attributes =
            {
                ["uid"] = "alice",
                ["departmentNumber"] = "Engineering",
                ["title"] = "Senior Developer"
            }
        };

        var result = mapper.MapToResult(entry);

        result.AdditionalClaims.Should().NotBeNull();
        result.AdditionalClaims.Should().ContainKey("department").WhoseValue.Should().Be("Engineering");
        result.AdditionalClaims.Should().ContainKey("title").WhoseValue.Should().Be("Senior Developer");
    }

    [Fact]
    public void MapToResult_EmptyAdditionalClaims_ReturnsNull()
    {
        var options = new LdapProviderOptions
        {
            UserBaseDn = "dc=test",
            AdditionalClaimsMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["department"] = "departmentNumber"
            }
        };
        options.ApplyPreset(LdapPreset.OpenLDAP);
        var mapper = new LdapAttributeMapper(options);

        var entry = new LdapEntry
        {
            Dn = "uid=alice,ou=users,dc=test",
            Attributes = { ["uid"] = "alice" }
        };

        var result = mapper.MapToResult(entry);

        result.AdditionalClaims.Should().BeNull();
    }

    // ── Mapper: GetRequestedAttributes ──

    [Fact]
    public void GetRequestedAttributes_IncludesFieldAndClaimsAttributes()
    {
        var options = new LdapProviderOptions
        {
            UserBaseDn = "dc=test",
            AttributeMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["externalId"] = "uid",
                ["email"] = "mail"
            },
            AdditionalClaimsMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["department"] = "departmentNumber"
            }
        };
        var mapper = new LdapAttributeMapper(options);

        var attrs = mapper.GetRequestedAttributes();

        attrs.Should().Contain("uid");
        attrs.Should().Contain("mail");
        attrs.Should().Contain("departmentNumber");
    }

    [Fact]
    public void GetRequestedAttributes_DeduplicatesOverlapping()
    {
        var options = new LdapProviderOptions
        {
            UserBaseDn = "dc=test",
            AttributeMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["email"] = "mail"
            },
            AdditionalClaimsMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["userEmail"] = "mail"
            }
        };
        var mapper = new LdapAttributeMapper(options);

        var attrs = mapper.GetRequestedAttributes();

        attrs.Should().ContainSingle(a => a.Equals("mail", StringComparison.OrdinalIgnoreCase));
    }
}
