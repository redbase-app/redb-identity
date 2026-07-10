using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using redb.Identity.Ldap;
using Xunit;

namespace redb.Identity.Tests.Ldap;

/// <summary>
/// Unit tests for <see cref="LdapSyncOptions"/>, <see cref="LdapSyncRouteBuilder"/>,
/// and sync DI registration.
/// </summary>
public class LdapSyncTests
{
    // ── LdapSyncOptions ──

    [Fact]
    public void SyncOptions_Defaults_AreReasonable()
    {
        var options = new LdapSyncOptions();

        options.RouteId.Should().Be("ldap-sync");
        options.Server.Should().Be("localhost");
        options.Port.Should().Be(389);
        options.PollIntervalMs.Should().Be(60_000);
        options.ChangeTrackingMode.Should().Be("ModifyTimestamp");
        options.InitialLoad.Should().BeTrue();
        options.DetectDeletions.Should().BeTrue();
        options.FullSyncInterval.Should().Be(10);
        options.ProviderName.Should().Be("ldap-sync");
        options.SyncGroups.Should().BeFalse();
        options.DisableDeletedUsers.Should().BeTrue();
        options.UserFilter.Should().Be("(objectClass=inetOrgPerson)");
    }

    [Fact]
    public void SyncOptions_Validate_ThrowsOnEmptyBaseDn()
    {
        var options = new LdapSyncOptions { UserBaseDn = "" };
        var act = () => options.Validate();
        act.Should().Throw<InvalidOperationException>().WithMessage("*UserBaseDn*");
    }

    [Fact]
    public void SyncOptions_Validate_ThrowsOnInvalidPollInterval()
    {
        var options = new LdapSyncOptions { UserBaseDn = "dc=test", PollIntervalMs = 0 };
        var act = () => options.Validate();
        act.Should().Throw<InvalidOperationException>().WithMessage("*PollIntervalMs*");
    }

    [Fact]
    public void SyncOptions_Validate_ThrowsOnNegativePollInterval()
    {
        var options = new LdapSyncOptions { UserBaseDn = "dc=test", PollIntervalMs = -1000 };
        var act = () => options.Validate();
        act.Should().Throw<InvalidOperationException>().WithMessage("*PollIntervalMs*");
    }

    [Fact]
    public void SyncOptions_Validate_ThrowsOnInvalidChangeTrackingMode()
    {
        var options = new LdapSyncOptions
        {
            UserBaseDn = "dc=test",
            ChangeTrackingMode = "invalid_mode"
        };
        var act = () => options.Validate();
        act.Should().Throw<InvalidOperationException>().WithMessage("*ChangeTrackingMode*");
    }

    [Theory]
    [InlineData("ModifyTimestamp")]
    [InlineData("modifytimestamp")]
    [InlineData("Usn")]
    [InlineData("Persistent")]
    public void SyncOptions_Validate_AcceptsValidChangeTrackingModes(string mode)
    {
        var options = new LdapSyncOptions
        {
            UserBaseDn = "dc=test",
            ChangeTrackingMode = mode
        };
        var act = () => options.Validate();
        act.Should().NotThrow();
    }

    [Fact]
    public void SyncOptions_Validate_ThrowsOnEmptyServer()
    {
        var options = new LdapSyncOptions
        {
            UserBaseDn = "dc=test",
            Server = ""
        };
        var act = () => options.Validate();
        act.Should().Throw<InvalidOperationException>().WithMessage("*Server*required*");
    }

    [Fact]
    public void SyncOptions_Validate_ThrowsOnSslAndStartTls()
    {
        var options = new LdapSyncOptions
        {
            UserBaseDn = "dc=test",
            UseSsl = true,
            UseStartTls = true
        };
        var act = () => options.Validate();
        act.Should().Throw<InvalidOperationException>().WithMessage("*mutually exclusive*");
    }

    [Fact]
    public void SyncOptions_Validate_PassesWithValidBaseDn()
    {
        var options = new LdapSyncOptions { UserBaseDn = "ou=users,dc=test" };
        var act = () => options.Validate();
        act.Should().NotThrow();
    }

    // ── LdapSyncRouteBuilder ──

    [Fact]
    public void SyncRouteBuilder_Constructor_ValidatesOptions()
    {
        var act = () => new LdapSyncRouteBuilder(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void SyncRouteBuilder_Constructor_ValidatesBaseDn()
    {
        var options = new LdapSyncOptions { UserBaseDn = "" };
        var act = () => new LdapSyncRouteBuilder(options);
        act.Should().Throw<InvalidOperationException>().WithMessage("*UserBaseDn*");
    }

    [Fact]
    public void SyncRouteBuilder_Constructor_AcceptsValidOptions()
    {
        var options = new LdapSyncOptions
        {
            UserBaseDn = "ou=users,dc=test",
            Server = "ldap.test",
            PollIntervalMs = 30_000
        };

        var builder = new LdapSyncRouteBuilder(options);
        builder.Should().NotBeNull();
    }

    // ── Sync DI registration ──

    [Fact]
    public void AddRedbIdentityLdapSync_RegistersHandler()
    {
        var sc = new ServiceCollection();
        sc.AddSingleton<ILoggerFactory>(NullLoggerFactory.Instance);
        sc.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));

        sc.AddRedbIdentityLdapSync(o =>
        {
            o.UserBaseDn = "ou=users,dc=test";
            o.ProviderName = "ldap-sync:corp";
        });

        using var sp = sc.BuildServiceProvider();

        var options = sp.GetRequiredService<LdapSyncOptions>();
        options.ProviderName.Should().Be("ldap-sync:corp");

        // Handler requires IRedbService which isn't registered here,
        // but the registration itself should succeed
        var descriptor = sc.FirstOrDefault(d => d.ServiceType == typeof(LdapSyncHandler));
        descriptor.Should().NotBeNull();
        descriptor!.Lifetime.Should().Be(ServiceLifetime.Scoped);
    }

    [Fact]
    public void AddRedbIdentityLdapSync_WithGroups_RegistersGroupMapper()
    {
        var sc = new ServiceCollection();
        sc.AddSingleton<ILoggerFactory>(NullLoggerFactory.Instance);
        sc.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));

        sc.AddRedbIdentityLdapSync(o =>
        {
            o.UserBaseDn = "ou=users,dc=test";
            o.SyncGroups = true;
            o.GroupMapperOptions.MemberRole = "viewer";
        });

        using var sp = sc.BuildServiceProvider();

        var groupOptions = sp.GetRequiredService<LdapGroupMapperOptions>();
        groupOptions.MemberRole.Should().Be("viewer");

        var descriptor = sc.FirstOrDefault(d => d.ServiceType == typeof(LdapGroupMapper));
        descriptor.Should().NotBeNull();
        descriptor!.Lifetime.Should().Be(ServiceLifetime.Scoped);
    }

    [Fact]
    public void AddRedbIdentityLdapSync_WithoutGroups_NoGroupMapper()
    {
        var sc = new ServiceCollection();

        sc.AddRedbIdentityLdapSync(o =>
        {
            o.UserBaseDn = "ou=users,dc=test";
            o.SyncGroups = false;
        });

        var descriptor = sc.FirstOrDefault(d => d.ServiceType == typeof(LdapGroupMapper));
        descriptor.Should().BeNull();
    }
}
