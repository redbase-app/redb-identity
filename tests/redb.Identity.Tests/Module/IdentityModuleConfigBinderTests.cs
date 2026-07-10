using System.Net;
using FluentAssertions;
using NSubstitute;
using redb.Identity.Contracts.Configuration;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Module;
using redb.Route.Abstractions;
using redb.Route.Core;
using Xunit;

namespace redb.Identity.Tests.Module;

/// <summary>
/// Verifies that <see cref="IdentityModuleConfigBinder"/> correctly hydrates
/// <see cref="RedbIdentityOptions"/> from the nested <c>IDictionary&lt;string, object?&gt;</c>
/// structure that Tsak deposits on the route context via <c>SetProperty</c>.
/// </summary>
public sealed class IdentityModuleConfigBinderTests
{
    private static IRouteContext MakeContext(IDictionary<string, object?>? identitySection)
    {
        var sp = Substitute.For<IServiceProvider>();
        var ctx = new RouteContext(sp, "_test");
        if (identitySection is not null)
            ctx.SetProperty(IdentityModuleConfigBinder.SectionName, identitySection);
        return ctx;
    }

    [Fact]
    public void Bind_ReturnsDefaults_WhenNoIdentitySection()
    {
        var opts = IdentityModuleConfigBinder.Bind(MakeContext(null));

        opts.Should().NotBeNull();
        opts.Issuer.Should().Be(new Uri("https://localhost/"));
        opts.RateLimit.Enabled.Should().BeFalse();
    }

    [Fact]
    public void Bind_HydratesScalarsAndTimespans()
    {
        var section = new Dictionary<string, object?>
        {
            ["RedbInstanceName"] = "identity-pg",
            ["Issuer"] = "https://identity.example.com/",
            ["AllowEphemeralKeys"] = "true",
            ["AccessTokenLifetime"] = "00:30:00",
            ["RecoveryCodePbkdf2Iterations"] = "750000",
            ["Features"] = new Dictionary<string, object?>
            {
                ["EnableDeviceCodeFlow"] = "true",
            },
        };

        var opts = IdentityModuleConfigBinder.Bind(MakeContext(section));

        opts.RedbInstanceName.Should().Be("identity-pg");
        opts.Issuer.Should().Be(new Uri("https://identity.example.com/"));
        opts.AllowEphemeralKeys.Should().BeTrue();
        opts.AccessTokenLifetime.Should().Be(TimeSpan.FromMinutes(30));
        opts.RecoveryCodePbkdf2Iterations.Should().Be(750_000);
        opts.Features.EnableDeviceCodeFlow.Should().BeTrue();
    }

    [Fact]
    public void Bind_HydratesNestedRateLimitOptions()
    {
        var section = new Dictionary<string, object?>
        {
            ["RateLimit"] = new Dictionary<string, object?>
            {
                ["Enabled"] = "true",
                ["PerIpPerMinute"] = "120",
                ["PerIpUsernameFailures"] = "3",
                ["PerIpUsernameWindow"] = "00:30:00",
                ["Backend"] = "redis",
                ["RedisConnectionString"] = "localhost:6379",
                ["RedisKeyPrefix"] = "myapp:rl:"
            }
        };

        var opts = IdentityModuleConfigBinder.Bind(MakeContext(section));

        opts.RateLimit.Enabled.Should().BeTrue();
        opts.RateLimit.PerIpPerMinute.Should().Be(120);
        opts.RateLimit.PerIpUsernameFailures.Should().Be(3);
        opts.RateLimit.PerIpUsernameWindow.Should().Be(TimeSpan.FromMinutes(30));
        opts.RateLimit.Backend.Should().Be("redis");
        opts.RateLimit.RedisConnectionString.Should().Be("localhost:6379");
        opts.RateLimit.RedisKeyPrefix.Should().Be("myapp:rl:");
    }

    [Fact]
    public void Bind_HydratesStringArrays()
    {
        var section = new Dictionary<string, object?>
        {
            ["DynamicRegistrationAllowedScopes"] = new List<object?> { "openid", "profile", "custom_scope" }
        };

        var opts = IdentityModuleConfigBinder.Bind(MakeContext(section));

        opts.DynamicRegistrationAllowedScopes.Should().Equal("openid", "profile", "custom_scope");
    }

    [Fact]
    public void Bind_HydratesFederationProvidersList()
    {
        var section = new Dictionary<string, object?>
        {
            ["Features"] = new Dictionary<string, object?>
            {
                ["EnableFederation"] = "true",
            },
            ["FederationProviders"] = new List<object?>
            {
                new Dictionary<string, object?>
                {
                    ["ProviderId"] = "google",
                    ["DisplayName"] = "Google",
                    ["Authority"] = "https://accounts.google.com",
                    ["ClientId"] = "client-1",
                    ["ClientSecret"] = "secret-1",
                    ["Priority"] = "10"
                }
            }
        };

        var opts = IdentityModuleConfigBinder.Bind(MakeContext(section));

        opts.Features.EnableFederation.Should().BeTrue();
        opts.FederationProviders.Should().HaveCount(1);
        opts.FederationProviders[0].ProviderId.Should().Be("google");
        opts.FederationProviders[0].Authority.Should().Be("https://accounts.google.com");
        opts.FederationProviders[0].Priority.Should().Be(10);
    }

    [Fact]
    public void Bind_ManuallyParsesIpAddressesAndNetworks()
    {
        var section = new Dictionary<string, object?>
        {
            ["ReverseProxies"] = new Dictionary<string, object?>
            {
                ["TrustForwardedFor"] = "true",
                ["KnownProxies"] = new List<object?> { "10.0.0.1", "203.0.113.7" },
                ["KnownNetworks"] = new List<object?> { "10.0.0.0/8", "192.168.0.0/16" }
            }
        };

        var opts = IdentityModuleConfigBinder.Bind(MakeContext(section));

        opts.ReverseProxies.TrustForwardedFor.Should().BeTrue();
        opts.ReverseProxies.KnownProxies.Should().HaveCount(2);
        opts.ReverseProxies.KnownProxies.Should().Contain(IPAddress.Parse("10.0.0.1"));
        opts.ReverseProxies.KnownNetworks.Should().HaveCount(2);
        opts.ReverseProxies.KnownNetworks[0].BaseAddress.Should().Be(IPAddress.Parse("10.0.0.0"));
        opts.ReverseProxies.KnownNetworks[0].PrefixLength.Should().Be(8);
    }
}
