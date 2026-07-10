using FluentAssertions;
using redb.Identity.Ldap;
using Xunit;

namespace redb.Identity.Tests.Ldap;

/// <summary>
/// Unit tests for <see cref="LdapConnectionSettings"/> validation.
/// </summary>
public class LdapConnectionSettingsTests
{
    // ── ValidateConnection ──

    [Fact]
    public void ValidateConnection_EmptyServer_Throws()
    {
        var settings = new LdapConnectionSettings { Server = "" };
        var act = () => settings.ValidateConnection();
        act.Should().Throw<InvalidOperationException>().WithMessage("*Server*required*");
    }

    [Fact]
    public void ValidateConnection_WhitespaceServer_Throws()
    {
        var settings = new LdapConnectionSettings { Server = "   " };
        var act = () => settings.ValidateConnection();
        act.Should().Throw<InvalidOperationException>().WithMessage("*Server*required*");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(70000)]
    public void ValidateConnection_PortOutOfRange_Throws(int port)
    {
        var settings = new LdapConnectionSettings { Port = port };
        var act = () => settings.ValidateConnection();
        act.Should().Throw<InvalidOperationException>().WithMessage("*Port*out of range*");
    }

    [Fact]
    public void ValidateConnection_SslAndStartTls_Throws()
    {
        var settings = new LdapConnectionSettings
        {
            UseSsl = true,
            UseStartTls = true
        };
        var act = () => settings.ValidateConnection();
        act.Should().Throw<InvalidOperationException>().WithMessage("*mutually exclusive*");
    }

    [Fact]
    public void ValidateConnection_BindDnWithoutPassword_Throws()
    {
        var settings = new LdapConnectionSettings
        {
            BindDn = "cn=admin,dc=test",
            BindPassword = null
        };
        var act = () => settings.ValidateConnection();
        act.Should().Throw<InvalidOperationException>().WithMessage("*BindDn*BindPassword*");
    }

    [Fact]
    public void ValidateConnection_PasswordWithoutBindDn_Throws()
    {
        var settings = new LdapConnectionSettings
        {
            BindDn = null,
            BindPassword = "secret"
        };
        var act = () => settings.ValidateConnection();
        act.Should().Throw<InvalidOperationException>().WithMessage("*BindPassword*BindDn*");
    }

    [Fact]
    public void ValidateConnection_ValidSettings_NoThrow()
    {
        var settings = new LdapConnectionSettings
        {
            Server = "ldap.test",
            Port = 636,
            UseSsl = true,
            BindDn = "cn=admin,dc=test",
            BindPassword = "secret"
        };
        var act = () => settings.ValidateConnection();
        act.Should().NotThrow();
    }

    [Fact]
    public void ValidateConnection_DefaultSettings_NoThrow()
    {
        var settings = new LdapConnectionSettings();
        var act = () => settings.ValidateConnection();
        act.Should().NotThrow();
    }

    // ── EffectivePort ──

    [Fact]
    public void EffectivePort_SslDefaultPort_Returns636()
    {
        var settings = new LdapConnectionSettings { UseSsl = true, Port = 389 };
        settings.EffectivePort.Should().Be(636);
    }

    [Fact]
    public void EffectivePort_SslCustomPort_ReturnsCustom()
    {
        var settings = new LdapConnectionSettings { UseSsl = true, Port = 10636 };
        settings.EffectivePort.Should().Be(10636);
    }

    [Fact]
    public void EffectivePort_NoSsl_ReturnsPlain()
    {
        var settings = new LdapConnectionSettings { Port = 389 };
        settings.EffectivePort.Should().Be(389);
    }

    // ── Defaults ──

    [Fact]
    public void Defaults_AreReasonable()
    {
        var settings = new LdapConnectionSettings();

        settings.Server.Should().Be("localhost");
        settings.Port.Should().Be(389);
        settings.UseSsl.Should().BeFalse();
        settings.UseStartTls.Should().BeFalse();
        settings.SkipCertificateValidation.Should().BeFalse();
        settings.BindDn.Should().BeNull();
        settings.BindPassword.Should().BeNull();
        settings.OperationTimeoutSeconds.Should().Be(10);
        settings.MaxConnections.Should().Be(5);
    }
}
