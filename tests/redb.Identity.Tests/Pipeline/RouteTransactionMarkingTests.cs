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
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;
using redb.Identity.Core.Routes;

namespace redb.Identity.Tests.Pipeline;

/// <summary>
/// G6 / E1 — verifies the route-level <c>IsTransacted</c> bit at definition time.
/// The bit is set by <c>WithRedbTx</c> / <c>WithIdempotentTx(wrapInRedbTx:true)</c>
/// in <see cref="IdentityCoreRouteBuilder"/> and is what guarantees rollback of
/// partial writes when a mid-pipeline exception fires.
/// <para>
/// As of commit 02d408a7 the mutation routes split into two architectural classes:
/// </para>
/// <list type="bullet">
///   <item>
///     <b>Still transacted (<see cref="MutatingRouteIds_StillTransacted"/>).</b>
///     The processor body writes through the per-exchange <c>IRedbService</c> that
///     <c>WithRedbTx</c> wraps — atomicity is real and load-bearing, e.g. Logout
///     revokes session + tokens in one route-level tx; Manage* CRUD writes multi-row
///     mutations against the same connection the wrap covers.
///   </item>
///   <item>
///     <b>No longer transacted (<see cref="MutatingRouteIds_NoLongerTransacted"/>).</b>
///     The processor's primary writers run through a DI-scoped store
///     (OpenIddict managers like <c>RedbApplicationStore</c> / <c>RedbTokenStore</c>,
///     or <c>_sp.GetService&lt;IPasswordHistoryStore&gt;()</c> et al.) that resolves
///     its own <c>IRedbService</c> on a separate DI scope. The route-level wrap
///     covered a different connection from the one doing the actual write; on SQLite
///     this held the writer lock during Argon2id + the OpenIddict pipeline (~30s)
///     while the store's separate connection raced against it on the same file, with
///     5s busy_timeout × ~7 retries surfacing as 34-second test latencies. The wrap
///     was removed because its atomicity guarantee was already false. The proper fix
///     for these flows is for those stores to share the per-exchange <c>IRedbService</c>
///     (separate refactor); the assert below pins the current architecture so the
///     wrap doesn't get silently re-added and bring the 34-second self-deadlock back.
///   </item>
/// </list>
/// </summary>
public sealed class RouteTransactionMarkingTests
{
    private readonly IdentityCoreRouteBuilder _builder;

    public RouteTransactionMarkingTests()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(Substitute.For<IRedbService>());

        // Critical: WithRedbTx is a no-op when RedbInstanceName is null. Production
        // bootstraps via AddRedbIdentityServer always populates this; mimic that here
        // so the assertions below test the production code path, not the dev fallback.
        services.AddSingleton(Options.Create(new RedbIdentityOptions
        {
            RedbInstanceName = "identity-test"
        }));

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

    public static IEnumerable<object[]> MutatingRouteIds_StillTransacted() => new[]
    {
        // OAuth/OIDC protocol routes whose primary writers go through the per-exchange
        // IRedbService that WithRedbTx wraps:
        new object[] { IdentityEndpoints.RouteIds.Logout },        // revokes session + tokens via _context's redb in one tx
        new object[] { IdentityEndpoints.RouteIds.ConsentGrant },  // grants consent through the per-exchange redb

        // Token — RESTORED. It was in the no-longer-transacted list below because the OpenIddict
        // stores resolved their IRedbService from Identity's child container, which opened a host
        // scope of its OWN per DI scope: a SECOND connection. The route wrap therefore covered a
        // different connection from the one doing the writes (no atomicity), and that second
        // connection deadlocked against the row locks the first one held.
        //
        // Fixed at the root: HostRedbScope now binds IRedbService to the exchange's instance (see
        // IdentityExchangeAccessor), so the stores write on the SAME connection the transaction was
        // opened on. One connection, one transaction, the stores enlisted in it — and the token
        // entry plus the authorization entry now either both land or neither does.
        new object[] { IdentityEndpoints.RouteIds.Token },

        // Management mutation endpoints — wrapped via WithIdempotentTx(wrapInRedbTx:true):
        new object[] { IdentityEndpoints.RouteIds.ManageScopes },
        new object[] { IdentityEndpoints.RouteIds.ManageUsers },
        new object[] { IdentityEndpoints.RouteIds.ManageTokens },
        new object[] { IdentityEndpoints.RouteIds.ManageGroups },
        new object[] { IdentityEndpoints.RouteIds.ManageConsents },
        new object[] { IdentityEndpoints.RouteIds.ManageSessions },
    };

    public static IEnumerable<object[]> MutatingRouteIds_NoLongerTransacted() => new[]
    {
        // Routes whose primary writers run through a store that opens its OWN DI scope from the
        // inside (PropsPasswordHistoryStore, ISigningKeyStore, FederationCallbackProcessor, …) and
        // therefore resolves its own IRedbService on a separate connection. The route-level wrap
        // would cover a different connection from the one doing the writes, and on SQLite that
        // produced ~34-second self-deadlocks (5 s busy_timeout × ~7 retries). Removed in 02d408a7.
        //
        // NOTE: Token has MOVED to the transacted list above. Its root cause was different — the
        // second connection came from HostRedbScope in the child container, not from a store calling
        // CreateScope() on itself — and that is now fixed (IdentityExchangeAccessor binds the child
        // scope's IRedbService to the exchange). The routes still listed here need the same
        // treatment: thread the exchange's IRedbService into those stores instead of letting them
        // open a scope. That is doc/PERF_RULES.md rule 1, and it is the remaining cleanup.
        new object[] { IdentityEndpoints.RouteIds.Authorize },
        new object[] { IdentityEndpoints.RouteIds.Revoke },
        new object[] { IdentityEndpoints.RouteIds.Login },
        new object[] { IdentityEndpoints.RouteIds.MfaVerify },
        new object[] { IdentityEndpoints.RouteIds.MfaRecovery },
        new object[] { IdentityEndpoints.RouteIds.MfaManage },
        new object[] { IdentityEndpoints.RouteIds.ManageApps },
    };

    [Theory]
    [MemberData(nameof(MutatingRouteIds_StillTransacted))]
    public void MutatingRoute_IsTransacted(string routeId)
    {
        var route = _builder.Definitions.FirstOrDefault(d => d.GetRouteId() == routeId);
        route.Should().NotBeNull("route '{0}' must be registered", routeId);

        route!.IsTransacted.Should().BeTrue(
            "E1: route '{0}' performs multi-row writes (auth, token, session, consent, " +
            "or admin mutation) and must run inside a redb transaction so that any " +
            "exception thrown after partial writes triggers rollback. WithRedbTx wires " +
            "this in IdentityCoreRouteBuilder; if a refactor drops it the route will " +
            "leak orphan rows on failure (per SPRINT-E/E1 spec).",
            routeId);
    }

    [Theory]
    [MemberData(nameof(MutatingRouteIds_NoLongerTransacted))]
    public void MutatingRoute_NoLongerTransacted(string routeId)
    {
        var route = _builder.Definitions.FirstOrDefault(d => d.GetRouteId() == routeId);
        route.Should().NotBeNull("route '{0}' must be registered", routeId);

        route!.IsTransacted.Should().BeFalse(
            "Route '{0}' had WithRedbTx removed in commit 02d408a7: its primary writers are stores " +
            "that open their OWN DI scope from the inside (PropsPasswordHistoryStore, " +
            "ISigningKeyStore, FederationCallbackProcessor, …) and so write on a second connection. " +
            "A route-level wrap would cover a different connection from the one doing the writes — " +
            "no atomicity — and the second connection then deadlocks against the row locks the " +
            "first one holds (~34 s on SQLite: 5 s busy_timeout × OnException retries). " +
            "Do NOT simply reinstate the wrap to make this assert pass: fix the root cause first, " +
            "the way Token was fixed — thread the exchange's IRedbService into those stores instead " +
            "of letting them call CreateScope(). See doc/PERF_RULES.md rule 1.",
            routeId);
    }

    [Fact]
    public void ReadOnlyDiscoveryRoutes_AreNotTransacted()
    {
        // Discovery / JWKS / userinfo / introspect are pure reads — wrapping them in
        // a tx adds latency and connection contention without correctness benefit.
        // If somebody accidentally bolted Transacted() onto them, JWKS/discovery
        // would start contending for write transactions on the redb pool.
        var readOnlyIds = new[]
        {
            IdentityEndpoints.RouteIds.Discovery,
            IdentityEndpoints.RouteIds.Jwks,
            IdentityEndpoints.RouteIds.Userinfo,
            IdentityEndpoints.RouteIds.Introspect,
            IdentityEndpoints.RouteIds.MfaListMethods,
        };

        foreach (var id in readOnlyIds)
        {
            var route = _builder.Definitions.FirstOrDefault(d => d.GetRouteId() == id);
            if (route is null) continue; // route is conditionally registered — skip

            route.IsTransacted.Should().BeFalse(
                "read-only route '{0}' must NOT carry a transaction wrapper — it would add " +
                "contention without atomicity benefit", id);
        }
    }
}
