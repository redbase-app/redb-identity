using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using NSubstitute;
using OpenIddict.Server;
using redb.Core;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.OpenIddict;
using redb.Identity.Contracts.Routes;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Definitions;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;
using redb.Identity.Core.Routes;

namespace redb.Identity.Tests.Cluster;

/// <summary>
/// G13 / A5 — clustered cleanup route marking.
/// <para>
/// Verifies that <c>identity-token-cleanup</c> and <c>identity-session-cleanup</c> timer
/// routes carry the <c>Cluster(true)</c> flag on their <see cref="IRouteDefinition"/>,
/// which is the mechanism that makes them leader-only in a clustered deployment.
/// In standalone mode the flag is silently ignored by the router, so the registration
/// itself is the only production-observable contract we can exercise here.
/// </para>
/// <para>
/// Multi-host leader/failover behaviour is asserted in the <c>redb.Route</c> cluster
/// test suite; here we only lock down the marking so that a refactor which accidentally
/// drops <c>.Cluster(true)</c> from a cleanup route is caught immediately.
/// </para>
/// </summary>
public sealed class ClusteredRouteMarkingTests
{
    private readonly IdentityCoreRouteBuilder _builder;

    public ClusteredRouteMarkingTests()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(Substitute.For<IRedbService>());
        services.AddSingleton(Options.Create(new RedbIdentityOptions()));

        services.AddDataProtection().UseEphemeralDataProtectionProvider();
        services.AddSingleton<MfaStateProtector>();
        services.AddSingleton<MfaSetupTokenProtector>();
        services.AddSingleton<MfaSecretProtector>();

        services.AddOpenIddict()
            .AddServer(options =>
            {
                options.EnableDegradedMode();
                options.SetIssuer(new Uri("https://identity.test.local/"));
                options.SetTokenEndpointUris("/connect/token");
                options.AllowClientCredentialsFlow();
                options.AddEphemeralEncryptionKey();
                options.AddEphemeralSigningKey();
                options.DisableAccessTokenEncryption();
                options.UseRedbRoute();

                options.AddEventHandler<ValidateTokenRequestContext>(builder =>
                    builder.UseInlineHandler(_ => default)
                        .SetOrder(int.MaxValue - 100_000).Build());
            });

        var sp = services.BuildServiceProvider();

        _builder = new IdentityCoreRouteBuilder(sp, sp.GetRequiredService<IOptions<RedbIdentityOptions>>());
        ((IRouteBuilder)_builder).Configure(null!);
    }

    [Theory]
    [InlineData("identity-token-cleanup")]
    [InlineData("identity-session-cleanup")]
    [InlineData("identity-mfa-otp-cleanup")]
    [InlineData("identity-revoked-sids-cleanup")]
    public void CleanupRoute_IsMarkedClustered(string routeId)
    {
        var route = _builder.Definitions.FirstOrDefault(d => d.GetRouteId() == routeId);

        route.Should().NotBeNull(
            "cleanup route '{0}' must be registered unconditionally (cleanup intervals default to non-zero)",
            routeId);

        route!.GetCluster().Should().BeTrue(
            "cleanup route '{0}' must carry .Cluster(true) so that in a clustered deployment " +
            "only the leader runs it (A5); dropping this flag would cause every replica to " +
            "race on cleanup and risks duplicate soft-deletes / double work",
            routeId);
    }

    [Fact]
    public void NonCleanupRoutes_AreNotMarkedClustered()
    {
        // Protocol/business routes must NOT be cluster-gated — they have to run on
        // every replica to serve traffic. If somebody accidentally bolted Cluster(true)
        // onto e.g. a token-issuance route, the non-leader replicas would stop
        // answering /connect/token and the deployment would brown-out.
        var clusteredIds = _builder.Definitions
            .Where(d => d.GetCluster())
            .Select(d => d.GetRouteId())
            .ToList();

        clusteredIds.Should().OnlyContain(
            id => id == "identity-token-cleanup"
                || id == "identity-session-cleanup"
                || id == "identity-mfa-otp-cleanup"
                || id == "identity-revoked-sids-cleanup",
            "only periodic cleanup routes may be marked Clustered; request-handling routes " +
            "must run on every replica. Offending routes: [{0}]",
            string.Join(", ", clusteredIds));
    }
}
