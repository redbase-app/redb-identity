using FluentAssertions;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging.Abstractions;
using redb.Identity.Core.Services;
using redb.Identity.Ldap;
using Xunit;

namespace redb.Identity.Tests.Ldap;

/// <summary>
/// Unit tests for <see cref="LdapHealthCheck"/>.
/// </summary>
public class LdapHealthCheckTests
{
    [Fact]
    public async Task NoProviders_ReturnsHealthy()
    {
        var check = new LdapHealthCheck(
            Array.Empty<IExternalUserProvider>(),
            NullLogger<LdapHealthCheck>.Instance);

        var result = await check.CheckHealthAsync(null!);

        result.Status.Should().Be(HealthStatus.Healthy);
        result.Description.Should().Contain("No LDAP providers");
    }

    [Fact]
    public async Task NonLdapProviders_ReturnsHealthy()
    {
        // IExternalUserProvider that is NOT LdapExternalUserProvider → filtered out
        var nonLdapProvider = new FakeExternalUserProvider();

        var check = new LdapHealthCheck(
            new IExternalUserProvider[] { nonLdapProvider },
            NullLogger<LdapHealthCheck>.Instance);

        var result = await check.CheckHealthAsync(null!);

        result.Status.Should().Be(HealthStatus.Healthy);
        result.Description.Should().Contain("No LDAP providers");
    }

    [Fact]
    public async Task UnreachableServer_ReturnsUnhealthy()
    {
        var options = new LdapProviderOptions
        {
            ProviderName = "ldap:fail",
            UserBaseDn = "dc=test",
            UserFilter = "(uid={0})",
            Server = "192.0.2.1", // RFC 5737 TEST-NET — not routable
            Port = 19999,
            OperationTimeoutSeconds = 2,
            ConnectTimeoutSeconds = 1 // pre-flight probe must fail fast
        };
        var provider = new LdapExternalUserProvider(
            options,
            NullLogger<LdapExternalUserProvider>.Instance);

        var context = new HealthCheckContext
        {
            Registration = new HealthCheckRegistration(
                "ldap-test", _ => throw new NotImplementedException(),
                HealthStatus.Degraded, null)
        };

        var check = new LdapHealthCheck(
            new IExternalUserProvider[] { provider },
            NullLogger<LdapHealthCheck>.Instance);

        var result = await check.CheckHealthAsync(context);

        result.Status.Should().NotBe(HealthStatus.Healthy);
        result.Data.Should().ContainKey("ldap:ldap:fail");
    }

    private sealed class FakeExternalUserProvider : IExternalUserProvider
    {
        public string ProviderName => "fake";
        public int Priority => 0;

        public Task<ExternalAuthResult?> AuthenticateAsync(
            string username, string password, CancellationToken ct = default)
            => Task.FromResult<ExternalAuthResult?>(null);
    }
}
