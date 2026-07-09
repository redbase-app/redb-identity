using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using redb.Core;
using redb.Core.Query;
using redb.Identity.Core.Configuration;
using redb.Identity.DataProtection;
using redb.Route.Abstractions;
using redb.Route.RedbCore.Extensions;

namespace redb.Identity.Core.Module;

/// <summary>
/// Builds a self-contained child <see cref="IServiceProvider"/> for the redb.Identity
/// .tpkg module. The Tsak.Worker root container is built BEFORE modules are loaded
/// (modules ship as plug-ins), so an Identity-internal DI graph is built lazily here
/// from the Tsak-resolved <see cref="RedbIdentityOptions"/>.
/// </summary>
/// <remarks>
/// <para>
/// Bridge services from the host root container:
/// <list type="bullet">
///   <item><see cref="ILoggerFactory"/> — shared logging plumbing.</item>
///   <item><see cref="TimeProvider"/> — testable clock (defaults to system).</item>
///   <item><see cref="IConfiguration"/> — host configuration root.</item>
///   <item><see cref="IRedbService"/> — resolved by name from the route context registry
///   so each Identity instance binds to the correct redb data source per
///   <see cref="RedbIdentityOptions.RedbInstanceName"/>.</item>
/// </list>
/// </para>
/// <para>
/// Identity-owned registrations (built fresh in the child container):
/// <list type="bullet">
///   <item><c>AddRedbIdentityServer(options)</c> — OpenIddict + Mfa + Login + Token + Federation + RateLimit.</item>
///   <item><c>AddDataProtection().PersistKeysToRedb()</c> — DataProtection key-ring stored in redb.</item>
///   <item><c>AddHttpClient()</c> — base infrastructure for federated OIDC HTTP calls.</item>
/// </list>
/// </para>
/// <para>
/// The returned <see cref="ServiceProvider"/> is owned by the caller and must be
/// disposed when the route context stops (see <see cref="ChildHostDisposeListener"/>).
/// </para>
/// </remarks>
internal static class IdentityModuleHost
{
    public static ServiceProvider Build(
        IRouteContext routeContext,
        RedbIdentityOptions options,
        Action<IServiceCollection>? extraRegistrations = null)
    {
        ArgumentNullException.ThrowIfNull(routeContext);
        ArgumentNullException.ThrowIfNull(options);        var rootSp = routeContext.GetServiceProvider()
                     ?? throw new InvalidOperationException(
                         "IRouteContext is missing a backing IServiceProvider — cannot bridge host services.");

        var services = new ServiceCollection();

        // 1. Bridge core host services.
        var loggerFactory = rootSp.GetRequiredService<ILoggerFactory>();
        services.AddSingleton(loggerFactory);
        services.AddLogging(); // wires Microsoft.Extensions.Logging.ILogger<T> against the bridged factory.

        services.AddSingleton(rootSp.GetService<TimeProvider>() ?? TimeProvider.System);

        var hostConfiguration = rootSp.GetService<IConfiguration>();
        if (hostConfiguration is not null)
            services.AddSingleton(hostConfiguration);

        // Bridge the host's IRouteContext into the child SP. The runtime that owns the
        // Identity routes (incl. direct-vm://identity-email-send) is the host context — child
        // services that publish into it (e.g. SmtpEmailNotificationChannel) need to resolve
        // IRouteContext from this child container, not from the host's. We bridge instead of
        // re-registering because the route context is a singleton per Tsak context, and
        // publishing into a *different* context would silently bypass the SMTP route entirely.
        services.AddSingleton(routeContext);

        // 2. IRedbService — bridged from the host as a SCOPED service.
        //
        // Why scoped (E7 follow-up): in the .tpkg topology redb.Route opens a per-exchange
        // child scope (exposed as IExchange.ServiceProvider) and OpenIddict resolves its
        // Scoped stores (RedbTokenStore, RedbAuthorizationStore, …) through that scope.
        // Production `AddRedbPro` registers IRedbService as Scoped — one per request,
        // backed by a fresh Npgsql connection from the pool. A Singleton bridge would
        // captive-capture one IRedbService for ALL concurrent requests, serialising the
        // whole Identity surface on a single connection. We instead bridge the host's
        // IServiceScopeFactory (or the named-instance factory registered by
        // TsakContextManager under `redb-factory:{name}`) and register a Scoped wrapper
        // that opens a host-side scope per child scope and disposes it deterministically.
        var redbInstanceName = options.RedbInstanceName?.TrimStart('#');
        IServiceScopeFactory hostRedbScopeFactory;
        if (!string.IsNullOrEmpty(redbInstanceName))
        {
            // Named instance — Tsak put a scope factory in the registry alongside the
            // singleton fallback. Use the factory so each child scope gets its own
            // IRedbService (and its own connection).
            hostRedbScopeFactory =
                routeContext.GetFromRegistry<IServiceScopeFactory>("redb-factory:" + redbInstanceName)
                ?? throw new InvalidOperationException(
                    $"Named IRedbService '{options.RedbInstanceName}' has no scope factory registered " +
                    $"in the route context (key 'redb-factory:{redbInstanceName}'). Did Tsak's " +
                    "RegisterNamedRedbServices run before module initialisation?");
        }
        else
        {
            // Default unnamed — bridge the host root provider's scope factory directly.
            hostRedbScopeFactory = rootSp.GetRequiredService<IServiceScopeFactory>();
        }

        // Wrap the host scope factory in a marker singleton so we DO NOT shadow the
        // child container's own IServiceScopeFactory registration (doing so would make
        // childSp.CreateScope() open scopes against the host container instead).
        var hostScopeFactoryHolder = new HostRedbScopeFactoryHolder(hostRedbScopeFactory);
        services.AddSingleton(hostScopeFactoryHolder);
        services.AddScoped<HostRedbScope>();
        services.AddScoped<IRedbService>(sp => sp.GetRequiredService<HostRedbScope>().Service);
        // 9f: bridge ISqlDialect from the host scope alongside IRedbService so listeners
        // (e.g. IdentityUniqueIndexesInitListener) can resolve the dialect against the
        // child container without falling back to host-only registrations.
        services.AddScoped<ISqlDialect>(sp => sp.GetRequiredService<HostRedbScope>().Dialect);

        // 3. Options snapshot.
        services.AddSingleton(Options.Create(options));
        services.AddOptions();

        // 4. HttpClient factory base — required by federation and any Identity HTTP egress.
        services.AddHttpClient();

        // 5. Identity itself.
        services.AddRedbIdentityServer(options);

        // 6. DataProtection persisted to redb (keys live in redb so all replicas share them).
        services.AddDataProtection()
            .SetApplicationName("redb.identity")
            .PersistKeysToRedb()
            .ProtectKeysWithRedbIdentity(options);

        // 7. Optional caller-supplied registrations (Variant B integrations such as LDAP
        //    that live in sibling assemblies and cannot be referenced from Core directly).
        extraRegistrations?.Invoke(services);

        // E7: enforce captive-dependency detection at build time. ValidateScopes catches
        // singletons capturing scoped services AND scoped services resolved from the root
        // provider; ValidateOnBuild fails fast on misconfigured DI instead of leaving a
        // latent bug for the first request to discover.
        return services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateScopes = true,
            ValidateOnBuild = true,
        });
    }
}

/// <summary>
/// Disposes the Identity child <see cref="IServiceProvider"/> when the surrounding route
/// context stops. Without this the child container would leak across Tsak hot-reloads.
/// </summary>
internal sealed class ChildHostDisposeListener : IRouteLifecycleListener
{
    private readonly ServiceProvider _childSp;

    public ChildHostDisposeListener(ServiceProvider childSp) => _childSp = childSp;

    public Task OnContextStopped(IRouteContext context, CancellationToken ct)
    {
        _childSp.Dispose();
        return Task.CompletedTask;
    }
}

/// <summary>
/// Per-child-scope wrapper around a host-side <see cref="IServiceScope"/> that exposes
/// <see cref="IRedbService"/> with deterministic disposal: when the Identity child scope
/// disposes (end of request), the bridged host scope disposes too, releasing the
/// underlying Npgsql connection back to the pool.
/// </summary>
/// <remarks>
/// This is the bridge between two independent DI universes: Tsak's host container (where
/// IRedbService is registered Scoped via <c>AddRedbPro</c> or named via <c>RedbInstanceFactory</c>)
/// and Identity's child container (which OpenIddict uses to resolve its stores per
/// per-exchange scope opened by redb.Route). Without this 1:1 mapping the alternative
/// would be a Singleton bridge that captive-captures one IRedbService for the lifetime
/// of the module — serialising every concurrent OpenIddict store call on a single
/// connection.
/// </remarks>
internal sealed class HostRedbScope : IDisposable, IAsyncDisposable
{
    private readonly IServiceScope _hostScope;
    public IRedbService Service { get; }
    public ISqlDialect Dialect { get; }

    public HostRedbScope(HostRedbScopeFactoryHolder holder)
    {
        _hostScope = holder.Factory.CreateScope();
        Service = _hostScope.ServiceProvider.GetRequiredService<IRedbService>();
        Dialect = _hostScope.ServiceProvider.GetRequiredService<ISqlDialect>();
    }

    public void Dispose() => _hostScope.Dispose();

    public ValueTask DisposeAsync() =>
        _hostScope is IAsyncDisposable a ? a.DisposeAsync() : new ValueTask(Task.Run(_hostScope.Dispose));
}

/// <summary>
/// Marker holder for the host's <see cref="IServiceScopeFactory"/>. Registered as a
/// distinct type (NOT as <c>IServiceScopeFactory</c> directly) so the child container
/// keeps its own scope factory intact while still being able to reach the host one
/// when bridging <see cref="IRedbService"/>.
/// </summary>
internal sealed class HostRedbScopeFactoryHolder
{
    public IServiceScopeFactory Factory { get; }
    public HostRedbScopeFactoryHolder(IServiceScopeFactory factory) => Factory = factory;
}
