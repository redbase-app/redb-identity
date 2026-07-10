using FluentAssertions;
using redb.Identity.Ldap;
using redb.Route.Ldap;
using Xunit;

namespace redb.Identity.Tests.Ldap;

/// <summary>
/// Unit tests for <see cref="LdapGroupMapper"/> logic.
/// Tests CN extraction from DNs and option defaults.
/// </summary>
public class LdapGroupMapperTests
{
    // ── ExtractCnFromDn ──

    [Theory]
    [InlineData("cn=developers,ou=groups,dc=example,dc=com", "developers")]
    [InlineData("CN=Admins,OU=Groups,DC=corp,DC=test", "Admins")]
    [InlineData("cn=single-group", "single-group")]
    [InlineData("cn=with spaces,ou=groups", "with spaces")]
    [InlineData("cn=Smith\\, John,ou=groups,dc=test", "Smith, John")]
    [InlineData("cn=Test\\+Group,ou=groups", "Test+Group")]
    [InlineData("cn=has\\\\backslash,ou=groups", "has\\backslash")]
    public void ExtractCnFromDn_ValidDn_ExtractsCn(string dn, string expected)
    {
        LdapGroupMapper.ExtractCnFromDn(dn).Should().Be(expected);
    }

    [Theory]
    [InlineData("ou=groups,dc=test")]           // not a CN
    [InlineData("uid=alice,ou=users,dc=test")]  // uid, not cn
    [InlineData("")]
    [InlineData(null)]
    [InlineData("   ")]
    public void ExtractCnFromDn_NotCn_ReturnsNull(string? dn)
    {
        LdapGroupMapper.ExtractCnFromDn(dn!).Should().BeNull();
    }

    // ── Options defaults ──

    [Fact]
    public void GroupMapperOptions_Defaults()
    {
        var options = new LdapGroupMapperOptions();

        options.GroupMemberAttribute.Should().Be("memberOf");
        options.MemberRole.Should().Be("member");
        options.AutoCreateGroups.Should().BeTrue();
        options.SyncStrategy.Should().Be(LdapGroupSyncStrategy.Full);
    }

    // ── LdapEntry memberOf extraction ──

    [Fact]
    public void LdapEntry_GetStringArray_ExtractsMemberOf()
    {
        var entry = new LdapEntry
        {
            Dn = "uid=alice,ou=users,dc=test",
            Attributes = new Dictionary<string, object>
            {
                ["memberOf"] = new[] { "cn=developers,ou=groups,dc=test", "cn=admins,ou=groups,dc=test" }
            }
        };

        var groups = entry.GetStringArray("memberOf");
        groups.Should().HaveCount(2);
        groups.Should().Contain("cn=developers,ou=groups,dc=test");
        groups.Should().Contain("cn=admins,ou=groups,dc=test");

        var names = groups!.Select(LdapGroupMapper.ExtractCnFromDn).ToArray();
        names.Should().Equal("developers", "admins");
    }

    [Fact]
    public void LdapEntry_NoMemberOf_ReturnsNull()
    {
        var entry = new LdapEntry
        {
            Dn = "uid=bob,ou=users,dc=test",
            Attributes = new Dictionary<string, object>
            {
                ["uid"] = "bob"
            }
        };

        entry.GetStringArray("memberOf").Should().BeNull();
    }
}
