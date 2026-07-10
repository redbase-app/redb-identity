using FluentAssertions;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using OpenIddict.Server;
using redb.Core;
using redb.Identity.Core.Health;
using redb.Tsak.Contracts;
using Xunit;

namespace redb.Identity.Tests.Health;

/// <summary>
/// Unit tests for <see cref="IdentityHealthContributor"/> covering the three probes
/// (database, signing-keys, data-protection) and the worst-status aggregation rule.
/// </summary>
public class IdentityHealthContributorTests
{
    [Fact]
    public async Task AllProbesGreen_ReturnsHealthy()
    {
        var sp = BuildProvider(dbVersion: "PostgreSQL 16.2", signingKeys: 1, dpKeys: 1);
        var contributor = new IdentityHealthContributor(sp, NullLogger<IdentityHealthContributor>.Instance);

        var status = await contributor.CheckHealthAsync(CancellationToken.None);

        status.Should().Be(HealthStatus.Healthy);
        contributor.ModuleName.Should().Be("identity");
    }

    [Fact]
    public async Task DatabaseUnreachable_ReturnsUnhealthy()
    {
        var redb = Substitute.For<IRedbService>();
        redb.GetDbVersionAsync(Arg.Any<CancellationToken>())
            .Returns<Task<string?>>(_ => throw new InvalidOperationException("DB down"));

        var sp = BuildProvider(redb: redb, signingKeys: 1, dpKeys: 1);
        var contributor = new IdentityHealthContributor(sp, NullLogger<IdentityHealthContributor>.Instance);

        var status = await contributor.CheckHealthAsync(CancellationToken.None);

        status.Should().Be(HealthStatus.Unhealthy);
    }

    [Fact]
    public async Task DatabaseEmptyVersion_ReturnsUnhealthy()
    {
        var sp = BuildProvider(dbVersion: "", signingKeys: 1, dpKeys: 1);
        var contributor = new IdentityHealthContributor(sp, NullLogger<IdentityHealthContributor>.Instance);

        var status = await contributor.CheckHealthAsync(CancellationToken.None);

        status.Should().Be(HealthStatus.Unhealthy);
    }

    [Fact]
    public async Task NoSigningKeys_ReturnsUnhealthy()
    {
        var sp = BuildProvider(dbVersion: "PostgreSQL 16.2", signingKeys: 0, dpKeys: 1);
        var contributor = new IdentityHealthContributor(sp, NullLogger<IdentityHealthContributor>.Instance);

        var status = await contributor.CheckHealthAsync(CancellationToken.None);

        status.Should().Be(HealthStatus.Unhealthy);
    }

    [Fact]
    public async Task NoDataProtectionKeys_ReturnsDegraded()
    {
        var sp = BuildProvider(dbVersion: "PostgreSQL 16.2", signingKeys: 1, dpKeys: 0);
        var contributor = new IdentityHealthContributor(sp, NullLogger<IdentityHealthContributor>.Instance);

        var status = await contributor.CheckHealthAsync(CancellationToken.None);

        status.Should().Be(HealthStatus.Degraded);
    }

    [Fact]
    public async Task DatabaseAndSigningBoth_Unhealthy_ReturnsUnhealthy()
    {
        // Worst-status wins: even though data-protection is fine, db+signing failure dominates.
        var sp = BuildProvider(dbVersion: "", signingKeys: 0, dpKeys: 1);
        var contributor = new IdentityHealthContributor(sp, NullLogger<IdentityHealthContributor>.Instance);

        var status = await contributor.CheckHealthAsync(CancellationToken.None);

        status.Should().Be(HealthStatus.Unhealthy);
    }

    [Fact]
    public async Task SigningOptionsMissing_ReturnsUnhealthy()
    {
        // No IOptionsMonitor<OpenIddictServerOptions> registered at all.
        var redb = Substitute.For<IRedbService>();
        redb.GetDbVersionAsync(Arg.Any<CancellationToken>()).Returns<string?>("v1");
        var keyManager = Substitute.For<IKeyManager>();
        keyManager.GetAllKeys().Returns(new List<IKey> { Substitute.For<IKey>() });

        var services = new ServiceCollection();
        services.AddScoped(_ => redb);
        services.AddSingleton(keyManager);
        var sp = services.BuildServiceProvider();

        var contributor = new IdentityHealthContributor(sp, NullLogger<IdentityHealthContributor>.Instance);

        var status = await contributor.CheckHealthAsync(CancellationToken.None);

        status.Should().Be(HealthStatus.Unhealthy);
    }

    [Fact]
    public async Task Cancellation_PropagatesFromDbProbe()
    {
        var redb = Substitute.For<IRedbService>();
        redb.GetDbVersionAsync(Arg.Any<CancellationToken>())
            .Returns<Task<string?>>(_ => throw new OperationCanceledException());

        var sp = BuildProvider(redb: redb, signingKeys: 1, dpKeys: 1);
        var contributor = new IdentityHealthContributor(sp, NullLogger<IdentityHealthContributor>.Instance);

        // OperationCanceledException is not caught — bubbles up so the probe respects cancellation.
        await Assert.ThrowsAsync<OperationCanceledException>(
            () => contributor.CheckHealthAsync(CancellationToken.None));
    }

    // -----------------------------------------------------------------------

    private static IServiceProvider BuildProvider(
        string? dbVersion = null,
        IRedbService? redb = null,
        int signingKeys = 0,
        int dpKeys = 0)
    {
        var services = new ServiceCollection();

        if (redb is null)
        {
            redb = Substitute.For<IRedbService>();
            redb.GetDbVersionAsync(Arg.Any<CancellationToken>()).Returns<string?>(dbVersion);
        }
        services.AddScoped(_ => redb);

        var serverOptions = new OpenIddictServerOptions();
        for (int i = 0; i < signingKeys; i++)
        {
            var bytes = new byte[64];
            Random.Shared.NextBytes(bytes);
            serverOptions.SigningCredentials.Add(new SigningCredentials(
                new SymmetricSecurityKey(bytes), SecurityAlgorithms.HmacSha256));
        }
        services.AddSingleton<IOptionsMonitor<OpenIddictServerOptions>>(
            new StaticOptionsMonitor<OpenIddictServerOptions>(serverOptions));

        var keyManager = Substitute.For<IKeyManager>();
        var keys = new List<IKey>();
        for (int i = 0; i < dpKeys; i++)
            keys.Add(Substitute.For<IKey>());
        keyManager.GetAllKeys().Returns(keys);
        services.AddSingleton(keyManager);

        return services.BuildServiceProvider();
    }

    private sealed class StaticOptionsMonitor<T> : IOptionsMonitor<T>
    {
        public StaticOptionsMonitor(T value) => CurrentValue = value;
        public T CurrentValue { get; }
        public T Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }
}
