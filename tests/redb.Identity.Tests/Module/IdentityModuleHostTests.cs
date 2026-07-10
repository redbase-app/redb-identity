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
}
