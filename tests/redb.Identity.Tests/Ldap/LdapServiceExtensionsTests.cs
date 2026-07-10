using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using redb.Identity.Core.Services;
using redb.Identity.Ldap;
using Xunit;

namespace redb.Identity.Tests.Ldap;

/// <summary>
/// Unit tests for <see cref="LdapServiceExtensions"/> DI registration.
/// </summary>
public class LdapServiceExtensionsTests
{
    private static ServiceCollection BaseServices()
    {
        var sc = new ServiceCollection();
        sc.AddSingleton<ILoggerFactory>(NullLoggerFactory.Instance);
        sc.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        return sc;
    }

    [Fact]
    public async Task AddRedbIdentityLdap_WithOptions_RegistersProvider()
    {
        var sc = BaseServices();
        var options = new LdapProviderOptions
        {
            UserBaseDn = "dc=test",
            UserFilter = "(uid={0})",
            ProviderName = "ldap:test"
        };

        sc.AddRedbIdentityLdap(options);

        await using var sp = sc.BuildServiceProvider();
        var provider = sp.GetRequiredService<IExternalUserProvider>();
        provider.Should().BeOfType<LdapExternalUserProvider>();
        provider.ProviderName.Should().Be("ldap:test");
    }

    [Fact]
    public void AddRedbIdentityLdap_WithOptions_RegistersOptionsAsSingleton()
    {
        var sc = BaseServices();
        var options = new LdapProviderOptions
        {
            UserBaseDn = "dc=test",
            UserFilter = "(uid={0})",
            Priority = 42
        };

        sc.AddRedbIdentityLdap(options);

        using var sp = sc.BuildServiceProvider();
        var resolved = sp.GetRequiredKeyedService<LdapProviderOptions>("ldap");
        resolved.Should().BeSameAs(options);
        resolved.Priority.Should().Be(42);
    }

    [Fact]
    public async Task AddRedbIdentityLdap_WithAction_ConfiguresAndRegisters()
    {
        var sc = BaseServices();

        sc.AddRedbIdentityLdap(o =>
        {
            o.UserBaseDn = "ou=people,dc=corp";
            o.UserFilter = "(sAMAccountName={0})";
            o.ProviderName = "ldap:corp";
            o.Server = "ldap.corp.test";
        });

        await using var sp = sc.BuildServiceProvider();
        var provider = sp.GetRequiredService<IExternalUserProvider>();
        provider.ProviderName.Should().Be("ldap:corp");

        var options = sp.GetRequiredKeyedService<LdapProviderOptions>("ldap:corp");
        options.Server.Should().Be("ldap.corp.test");
    }

    [Fact]
    public async Task AddRedbIdentityLdap_WithConfiguration_BindsSection()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Server"] = "ldap.example.com",
                ["Port"] = "636",
                ["UseSsl"] = "true",
                ["UserBaseDn"] = "ou=users,dc=example,dc=com",
                ["UserFilter"] = "(uid={0})",
                ["BindDn"] = "cn=svc,dc=example,dc=com",
                ["BindPassword"] = "secret",
                ["ProviderName"] = "ldap:bound"
            })
            .Build();

        var sc = BaseServices();
        sc.AddRedbIdentityLdap(config);

        await using var sp = sc.BuildServiceProvider();
        var provider = sp.GetRequiredService<IExternalUserProvider>();
        provider.ProviderName.Should().Be("ldap:bound");

        var options = sp.GetRequiredKeyedService<LdapProviderOptions>("ldap:bound");
        options.Server.Should().Be("ldap.example.com");
        options.Port.Should().Be(636);
        options.UseSsl.Should().BeTrue();
        options.BindDn.Should().Be("cn=svc,dc=example,dc=com");
    }

    [Fact]
    public void AddRedbIdentityLdap_NullOptions_ThrowsArgumentNull()
    {
        var sc = BaseServices();

        var act = () => sc.AddRedbIdentityLdap((LdapProviderOptions)null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void AddRedbIdentityLdap_InvalidOptions_ThrowsOnResolve()
    {
        var sc = BaseServices();
        sc.AddRedbIdentityLdap(o =>
        {
            o.UserBaseDn = ""; // invalid
        });

        using var sp = sc.BuildServiceProvider();

        // Provider constructor calls Validate() which throws
        var act = () => sp.GetRequiredService<IExternalUserProvider>();
        act.Should().Throw<InvalidOperationException>().WithMessage("*UserBaseDn*");
    }

    // ── Multi-provider ──

    [Fact]
    public async Task MultiProvider_ResolvesAllProviders()
    {
        var sc = BaseServices();

        sc.AddRedbIdentityLdap(new LdapProviderOptions
        {
            ProviderName = "ldap:corp",
            UserBaseDn = "dc=corp",
            UserFilter = "(uid={0})",
            Server = "corp.test"
        });
        sc.AddRedbIdentityLdap(new LdapProviderOptions
        {
            ProviderName = "ldap:vendor",
            UserBaseDn = "dc=vendor",
            UserFilter = "(uid={0})",
            Server = "vendor.test"
        });

        await using var sp = sc.BuildServiceProvider();
        var providers = sp.GetServices<IExternalUserProvider>().ToArray();

        providers.Should().HaveCount(2);
        providers.Select(p => p.ProviderName).Should().BeEquivalentTo("ldap:corp", "ldap:vendor");
    }

    [Fact]
    public void MultiProvider_KeyedOptionsAreSeparate()
    {
        var sc = BaseServices();

        sc.AddRedbIdentityLdap(new LdapProviderOptions
        {
            ProviderName = "ldap:a",
            UserBaseDn = "dc=a",
            UserFilter = "(uid={0})",
            Server = "a.test",
            Priority = 10
        });
        sc.AddRedbIdentityLdap(new LdapProviderOptions
        {
            ProviderName = "ldap:b",
            UserBaseDn = "dc=b",
            UserFilter = "(uid={0})",
            Server = "b.test",
            Priority = 20
        });

        using var sp = sc.BuildServiceProvider();
        var optA = sp.GetRequiredKeyedService<LdapProviderOptions>("ldap:a");
        var optB = sp.GetRequiredKeyedService<LdapProviderOptions>("ldap:b");

        optA.Server.Should().Be("a.test");
        optA.Priority.Should().Be(10);
        optB.Server.Should().Be("b.test");
        optB.Priority.Should().Be(20);
    }

    // ── Health check registration ──

    [Fact]
    public void AddRedbIdentityLdapCheck_RegistersHealthCheck()
    {
        var sc = BaseServices();
        sc.AddHealthChecks()
            .AddRedbIdentityLdapCheck();

        using var sp = sc.BuildServiceProvider();
        var healthCheckService = sp.GetService<Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckService>();
        healthCheckService.Should().NotBeNull();
    }
}
