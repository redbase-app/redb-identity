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
        var hostScopeFactoryHolder = new HostRedbScopeFactoryHolder(hostRedbScopeFactory, redbInstanceName);
        services.AddSingleton(hostScopeFactoryHolder);

        // Carries the exchange this child scope was opened for. Seeded by whoever opens the scope
        // (IdentityRouteContextExtensions / RedbRouteOpenIddictServerHandler); read by HostRedbScope,
        // which uses it to bind IRedbService to the exchange's connection instead of opening a
        // second one. Without this, nothing inside the child container can join a route-level redb
        // transaction — see HostRedbScope's remarks and doc/PERF_RULES.md rule 1.
        services.AddScoped<IdentityExchangeAccessor>();

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
/// Bridges <see cref="IRedbService"/> from Tsak's host container into Identity's child container,
/// and — critically — makes sure that inside a route it is the <b>same</b> instance, and therefore
/// the same DB connection, that any route-level redb transaction was opened on.
/// </summary>
/// <remarks>
/// <para>
/// Two independent DI universes: Tsak's host container (where <see cref="IRedbService"/> is Scoped
/// via <c>AddRedbPro</c>, or named via <c>RedbInstanceFactory</c>) and Identity's child container,
/// from which OpenIddict resolves its stores. This class is the bridge.
/// </para>
/// <para>
/// <b>The bug this fixes.</b> It used to open its own host scope in the constructor —
/// unconditionally, eagerly. That is a <b>second</b> connection. A route-level transaction
/// (<c>BeginRedbTransaction</c>) runs on the connection redb.Route caches on the exchange, so the
/// OpenIddict stores were writing on a different one: no atomicity at all, and worse — the second
/// connection blocks on row locks the first one holds, while the first is awaiting the very call
/// that opened the second. Deadlock, cleared only by the 30s transaction timeout. That is exactly
/// rule 1 of <c>doc/PERF_RULES.md</c> ("do not open a fresh DI scope inside a route processor that
/// runs under a transaction"), and it is why <c>WithRedbTx</c> had to be stripped from the token
/// route. It is not a SQLite quirk: the rule is written about Npgsql. SQLite (single writer) only
/// makes the symptom louder.
/// </para>
/// <para>
/// <b>The fix.</b> When the scope belongs to an exchange, ask redb.Route for the exchange's
/// <see cref="IRedbService"/> — the very instance it caches in <c>IExchange.Properties</c> and hands
/// to <c>BeginRedbTransaction</c>. One connection, one transaction, everybody enlisted. Only when
/// there is no exchange (hosted services, cleanup timers, schema init) do we fall back to opening a
/// host scope of our own, which is correct: there is no ambient transaction to join.
/// </para>
/// <para>
/// Resolution is lazy. A scope that never touches the DB no longer pays for a connection.
/// </para>
/// </remarks>
internal sealed class HostRedbScope : IDisposable, IAsyncDisposable
{
    private readonly HostRedbScopeFactoryHolder _holder;
    private readonly IdentityExchangeAccessor _accessor;
    private readonly IRouteContext _routeContext;
    private readonly string? _redbName;

    private IServiceScope? _ownScope;   // opened ONLY on the no-exchange path
    private IRedbService? _service;
    private ISqlDialect? _dialect;

    public HostRedbScope(
        HostRedbScopeFactoryHolder holder,
        IdentityExchangeAccessor accessor,
        IRouteContext routeContext)
    {
        _holder = holder;
        _accessor = accessor;
        _routeContext = routeContext;
        _redbName = holder.RedbInstanceName;
    }

    public IRedbService Service => _service ??= ResolveService();

    public ISqlDialect Dialect => _dialect ??= ResolveDialect();

    private IRedbService ResolveService()
    {
        // In-route: take the exchange's instance. This is the whole point — it is the connection
        // BeginRedbTransaction opened the transaction on, so our writes land inside it.
        if (_accessor.Exchange is { } exchange)
            return _routeContext.GetRedbService(_redbName ?? string.Empty, exchange);

        // Out-of-route (timers, hosted services, init): no ambient transaction exists, so an own
        // scope is both safe and necessary.
        return EnsureOwnScope().ServiceProvider.GetRequiredService<IRedbService>();
    }

    private ISqlDialect ResolveDialect()
    {
        // The dialect is a stateless SQL-shape helper, not a connection — but resolve it from the
        // exchange's provider when we can, rather than opening a scope purely to reach it.
        if (_accessor.Exchange?.ServiceProvider?.GetService<ISqlDialect>() is { } fromExchange)
            return fromExchange;

        return EnsureOwnScope().ServiceProvider.GetRequiredService<ISqlDialect>();
    }

    private IServiceScope EnsureOwnScope() => _ownScope ??= _holder.Factory.CreateScope();

    public void Dispose() => _ownScope?.Dispose();

    public ValueTask DisposeAsync()
    {
        if (_ownScope is null) return ValueTask.CompletedTask;
        var scope = _ownScope;
        _ownScope = null;
        return scope is IAsyncDisposable a ? a.DisposeAsync() : new ValueTask(Task.Run(scope.Dispose));
    }
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

    /// <summary>
    /// The named redb instance this module runs on (already trimmed of the leading '#'), or null
    /// for the default unnamed one. <see cref="HostRedbScope"/> needs it to ask redb.Route for the
    /// exchange's instance under the same name the route transaction was opened on.
    /// </summary>
    public string? RedbInstanceName { get; }

    public HostRedbScopeFactoryHolder(IServiceScopeFactory factory, string? redbInstanceName = null)
    {
        Factory = factory;
        RedbInstanceName = redbInstanceName;
    }
}
