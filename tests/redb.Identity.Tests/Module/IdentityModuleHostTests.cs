using FluentAssertions;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using OpenIddict.Server;
using redb.Core;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Module;
using redb.Identity.Core.Services;
using redb.Route.Core;
using redb.Route.RedbCore.Extensions;
using Xunit;
using redb.Identity.Core.Routes;

namespace redb.Identity.Tests.Module;

/// <summary>
/// Smoke tests for <see cref="IdentityModuleHost"/> — verifies that the child
/// <see cref="ServiceProvider"/> built for the .tpkg path resolves all the services that
/// the existing <c>IdentityCoreRouteBuilder</c> depends on, without requiring the host
/// to pre-register Identity in the root container.
/// </summary>
public sealed class IdentityModuleHostTests
{
    private static (RouteContext Ctx, IRedbService Redb) MakeContext()
    {
        var rootServices = new ServiceCollection();
        rootServices.AddSingleton<ILoggerFactory>(NullLoggerFactory.Instance);
        rootServices.AddLogging();
        var rootSp = rootServices.BuildServiceProvider();

        var ctx = new RouteContext(rootSp, "_test", NullLoggerFactory.Instance);
        var redb = Substitute.For<IRedbService>();

        // The production bridge resolves IRedbService through an IServiceScopeFactory
        // looked up at "redb-factory:{name}" (so each child-scope request becomes a
        // host-side scope and the underlying IRedbService is Scoped). Build a tiny
        // host SP that registers the substitute as Scoped so per-scope resolutions
        // still return the same reference under our control.
        var hostServices = new ServiceCollection();
        hostServices.AddScoped<IRedbService>(_ => redb);
        // HostRedbScope now also resolves ISqlDialect from the host scope so the
        // child container can bridge dialect-aware services without re-registration.
        hostServices.AddScoped<redb.Core.Query.ISqlDialect>(_ => Substitute.For<redb.Core.Query.ISqlDialect>());
        var hostSp = hostServices.BuildServiceProvider();
        ctx.AddToRegistry("redb-factory:identity-pg", hostSp.GetRequiredService<IServiceScopeFactory>());
        return (ctx, redb);
    }

    [Fact]
    public void Build_WithEphemeralKeys_ResolvesIdentityOptionsAndCoreServices()
    {
        var (ctx, _) = MakeContext();
        var opts = new RedbIdentityOptions
        {
            RedbInstanceName = "identity-pg",
            AllowEphemeralKeys = true,
            DisableAccessTokenEncryption = true
        };

        using var childSp = IdentityModuleHost.Build(ctx, opts);

        childSp.GetRequiredService<IOptions<RedbIdentityOptions>>().Value.AllowEphemeralKeys
            .Should().BeTrue();
        childSp.GetService<TimeProvider>().Should().NotBeNull();
        childSp.GetService<ILoggerFactory>().Should().NotBeNull();
        childSp.GetService<IXmlRepository>().Should().NotBeNull("PersistKeysToRedb must register IXmlRepository");
        childSp.GetService<MfaStateProtector>().Should().NotBeNull();
        childSp.GetService<IOptionsMonitor<OpenIddictServerOptions>>()
            .Should().NotBeNull("AddRedbIdentityServer must wire up OpenIddict server options");
    }

    [Fact]
    public void Build_WithRateLimitMemoryBackend_ResolvesInMemoryStore()
    {
        var (ctx, _) = MakeContext();
        var opts = new RedbIdentityOptions
        {
            AllowEphemeralKeys = true,
            DisableAccessTokenEncryption = true,
            RateLimit = new RateLimitOptions { Enabled = true, Backend = "memory" }
        };

        using var childSp = IdentityModuleHost.Build(ctx, opts);

        var store = childSp.GetService<IRateLimitStore>();
        store.Should().NotBeNull();
        store.Should().BeOfType<InMemoryRateLimitStore>();
    }

    [Fact]
    public void Build_BridgesIRedbServiceFromRouteContextRegistry()
    {
        var (ctx, expected) = MakeContext();
        var opts = new RedbIdentityOptions
        {
            RedbInstanceName = "identity-pg",
            AllowEphemeralKeys = true,
            DisableAccessTokenEncryption = true
        };

        using var childSp = IdentityModuleHost.Build(ctx, opts);

        // IRedbService is Scoped inside the child container (per-exchange lifestyle),
        // so we must open a scope to resolve it — exactly what redb.Route does per HTTP
        // exchange via IExchange.ServiceProvider.
        using var scope = childSp.CreateScope();
        var bridged = scope.ServiceProvider.GetRequiredService<IRedbService>();
        ReferenceEquals(bridged, expected).Should().BeTrue(
            "the child container must reuse the IRedbService registered in the route context registry");
    }

    [Fact]
    public async Task ChildHostDisposeListener_DisposesChildSpOnContextStopped()
    {
        var (ctx, _) = MakeContext();
        var opts = new RedbIdentityOptions
        {
            AllowEphemeralKeys = true,
            DisableAccessTokenEncryption = true
        };
        var childSp = IdentityModuleHost.Build(ctx, opts);
        var listener = new ChildHostDisposeListener(childSp);

        await listener.OnContextStopped(ctx, default);

        Action act = () => childSp.GetRequiredService<IOptions<RedbIdentityOptions>>();
        act.Should().Throw<ObjectDisposedException>();
    }

    // ── The transaction-enlistment contract ───────────────────────────────────────────────────
    //
    // These two are the proof that `WithRedbTx` on the token route is meaningful again, and they
    // are deliberately written at the layer where the bug actually lived: the .tpkg child
    // container. A test built on a single-SP host would pass with OR without the fix — in that
    // topology the OpenIddict handler already runs on the exchange's own scope — and would prove
    // nothing while looking like proof.
    //
    // The host factory below hands out a DISTINCT IRedbService per scope, exactly like production
    // (each scope = its own DB connection). That is what makes "same reference" a real assertion
    // rather than an artefact of the fixture.

    /// <summary>
    /// Route context whose named redb factory yields a FRESH <see cref="IRedbService"/> per scope —
    /// one connection per scope, as in production. Reference equality therefore means "the same
    /// connection", which is the whole question here.
    /// </summary>
    private static RouteContext MakeContextWithDistinctRedbPerScope()
    {
        var rootServices = new ServiceCollection();
        rootServices.AddSingleton<ILoggerFactory>(NullLoggerFactory.Instance);
        rootServices.AddLogging();
        var rootSp = rootServices.BuildServiceProvider();

        var ctx = new RouteContext(rootSp, "_test_tx", NullLoggerFactory.Instance);

        var hostServices = new ServiceCollection();
        hostServices.AddScoped<IRedbService>(_ => Substitute.For<IRedbService>());
        hostServices.AddScoped<redb.Core.Query.ISqlDialect>(_ => Substitute.For<redb.Core.Query.ISqlDialect>());
        var hostSp = hostServices.BuildServiceProvider();

        ctx.AddToRegistry("redb-factory:identity-pg", hostSp.GetRequiredService<IServiceScopeFactory>());
        return ctx;
    }

    private static RedbIdentityOptions TxOptions() => new()
    {
        RedbInstanceName = "identity-pg",
        AllowEphemeralKeys = true,
        DisableAccessTokenEncryption = true
    };

    [Fact]
    public void ChildScope_BoundToExchange_ResolvesTheExchangeRedbService()
    {
        var ctx = MakeContextWithDistinctRedbPerScope();
        using var childSp = IdentityModuleHost.Build(ctx, TxOptions());

        var exchange = new Exchange();

        // The instance a route-level BeginRedbTransaction opens its transaction on. redb.Route
        // caches its scope on the exchange, so every later ask for the same name returns this one.
        var transactionService = ctx.GetRedbService("identity-pg", exchange);

        // What an OpenIddict store gets: a child-container scope, told which exchange it serves.
        using var scope = childSp.CreateScope();
        scope.ServiceProvider.GetRequiredService<IdentityExchangeAccessor>().Exchange = exchange;
        var storeService = scope.ServiceProvider.GetRequiredService<IRedbService>();

        ReferenceEquals(storeService, transactionService).Should().BeTrue(
            "the OpenIddict stores must write on the SAME IRedbService — and therefore the same DB " +
            "connection — that the route transaction was opened on. When they did not, the wrap " +
            "covered a connection nobody was writing on (no atomicity at all), and the stores' own " +
            "connection then deadlocked against the row locks the transaction held while the " +
            "transaction awaited them. That is why WithRedbTx had to be stripped from the token " +
            "route; this assertion is what lets it come back. See doc/PERF_RULES.md rule 1.");
    }

    [Fact]
    public void ChildScope_WithoutExchange_GetsItsOwnRedbService()
    {
        var ctx = MakeContextWithDistinctRedbPerScope();
        using var childSp = IdentityModuleHost.Build(ctx, TxOptions());

        // Out-of-route callers — cleanup timers, hosted services, schema init — have no exchange and
        // therefore no ambient transaction to join. They must get their own scope: taking somebody
        // else's connection would be worse than the bug we just fixed.
        using var scopeA = childSp.CreateScope();
        using var scopeB = childSp.CreateScope();

        var a = scopeA.ServiceProvider.GetRequiredService<IRedbService>();
        var b = scopeB.ServiceProvider.GetRequiredService<IRedbService>();

        ReferenceEquals(a, b).Should().BeFalse(
            "with no exchange there is no transaction to enlist in, so each scope must keep its own " +
            "connection — otherwise concurrent background work would serialise onto one connection " +
            "(the captive-singleton trap this bridge exists to avoid)");
    }
}
