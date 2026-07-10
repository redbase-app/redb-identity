using FluentAssertions;
using redb.Identity.Ldap;
using Xunit;

namespace redb.Identity.Tests.Ldap;

/// <summary>
/// Unit tests for <see cref="LdapProviderOptions"/> validation and configuration.
/// </summary>
public class LdapProviderOptionsTests
{
    [Fact]
    public void Validate_ThrowsOnEmptyUserBaseDn()
    {
        var options = new LdapProviderOptions { UserBaseDn = "" };
        var act = () => options.Validate();
        act.Should().Throw<InvalidOperationException>().WithMessage("*UserBaseDn*");
    }

    [Fact]
    public void Validate_ThrowsOnFilterWithoutPlaceholder()
    {
        var options = new LdapProviderOptions
        {
            UserBaseDn = "dc=test",
            UserFilter = "(uid=alice)"
        };
        var act = () => options.Validate();
        act.Should().Throw<InvalidOperationException>().WithMessage("*{0}*");
    }

    [Fact]
    public void Validate_ThrowsOnInvalidPort()
    {
        var options = new LdapProviderOptions
        {
            UserBaseDn = "dc=test",
            Port = 0
        };
        var act = () => options.Validate();
        act.Should().Throw<InvalidOperationException>().WithMessage("*Port*");
    }

    [Fact]
    public void Validate_PassesWithValidOptions()
    {
        var options = new LdapProviderOptions
        {
            UserBaseDn = "ou=users,dc=example,dc=com",
            UserFilter = "(uid={0})"
        };
        var act = () => options.Validate();
        act.Should().NotThrow();
    }

    [Fact]
    public void EffectivePort_Returns636_WhenSslAndDefaultPort()
    {
        var options = new LdapProviderOptions { UseSsl = true, Port = 389 };
        options.EffectivePort.Should().Be(636);
    }

    [Fact]
    public void EffectivePort_ReturnsCustomPort_WhenSslOnCustomPort()
    {
        var options = new LdapProviderOptions { UseSsl = true, Port = 10636 };
        options.EffectivePort.Should().Be(10636);
    }

    [Fact]
    public void EffectivePort_ReturnsPlainPort_WhenNoSsl()
    {
        var options = new LdapProviderOptions { Port = 389 };
        options.EffectivePort.Should().Be(389);
    }

    [Fact]
    public void Defaults_AreReasonable()
    {
        var options = new LdapProviderOptions();

        options.ProviderName.Should().Be("ldap");
        options.Priority.Should().Be(100);
        options.Server.Should().Be("localhost");
        options.Port.Should().Be(389);
        options.UseSsl.Should().BeFalse();
        options.UseStartTls.Should().BeFalse();
        options.SearchScope.Should().Be(LdapSearchScopeOption.Subtree);
        options.UserFilter.Should().Be("(uid={0})");
        options.MaxConnections.Should().Be(5);
        options.Domains.Should().BeEmpty();
    }

    [Fact]
    public void ApplyPreset_OverwritesExistingMap()
    {
        var options = new LdapProviderOptions
        {
            UserBaseDn = "dc=test",
            AttributeMap = new Dictionary<string, string> { ["custom"] = "field" }
        };

        options.ApplyPreset(LdapPreset.ActiveDirectory);

        options.AttributeMap.Should().NotContainKey("custom");
        options.AttributeMap.Should().ContainKey("externalId");
    }

    // ── Validate delegation to ValidateConnection ──

    [Fact]
    public void Validate_EmptyServer_Throws()
    {
        var options = new LdapProviderOptions
        {
            Server = "",
            UserBaseDn = "dc=test",
            UserFilter = "(uid={0})"
        };
        var act = () => options.Validate();
        act.Should().Throw<InvalidOperationException>().WithMessage("*Server*required*");
    }

    [Fact]
    public void Validate_SslAndStartTls_Throws()
    {
        var options = new LdapProviderOptions
        {
            UseSsl = true,
            UseStartTls = true,
            UserBaseDn = "dc=test",
            UserFilter = "(uid={0})"
        };
        var act = () => options.Validate();
        act.Should().Throw<InvalidOperationException>().WithMessage("*mutually exclusive*");
    }

    // ── NormalizeAfterBind ──

    [Fact]
    public void NormalizeAfterBind_RestoresCaseInsensitiveComparer()
    {
        var options = new LdapProviderOptions();
        // Simulate what IConfiguration.Bind() does: replace with case-sensitive dict
        options.AttributeMap = new Dictionary<string, string>
        {
            ["ExternalId"] = "uid",
            ["DisplayName"] = "cn"
        };
        options.AdditionalClaimsMap = new Dictionary<string, string>
        {
            ["Department"] = "dept"
        };

        options.AttributeMap.Comparer.Should().NotBe(StringComparer.OrdinalIgnoreCase);

        options.NormalizeAfterBind();

        options.AttributeMap.Comparer.Should().Be(StringComparer.OrdinalIgnoreCase);
        options.AttributeMap["externalid"].Should().Be("uid");
        options.AdditionalClaimsMap["department"].Should().Be("dept");
    }

    [Fact]
    public void NormalizeAfterBind_AlreadyCaseInsensitive_NoOp()
    {
        var options = new LdapProviderOptions();
        var originalMap = options.AttributeMap;

        options.NormalizeAfterBind();

        options.AttributeMap.Should().BeSameAs(originalMap);
    }

    // ── CheckAccountStatus ──

    [Fact]
    public void CheckAccountStatus_DefaultFalse()
    {
        var options = new LdapProviderOptions();
        options.CheckAccountStatus.Should().BeFalse();
    }

    [Fact]
    public void ApplyPreset_AD_SetsCheckAccountStatusTrue()
    {
        var options = new LdapProviderOptions { UserBaseDn = "dc=test" };
        options.ApplyPreset(LdapPreset.ActiveDirectory);

        options.CheckAccountStatus.Should().BeTrue();
        options.UserFilter.Should().Contain("sAMAccountName");
    }

    [Fact]
    public void ApplyPreset_OpenLDAP_DoesNotSetCheckAccountStatus()
    {
        var options = new LdapProviderOptions { UserBaseDn = "dc=test" };
        options.ApplyPreset(LdapPreset.OpenLDAP);

        options.CheckAccountStatus.Should().BeFalse();
    }
}
