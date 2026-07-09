using Microsoft.Extensions.DependencyInjection;
using redb.Route.Abstractions;

namespace redb.Identity.Core.Module;

/// <summary>
/// Bridges Identity-owned services (OpenIddict managers, deletion service, options snapshot, …)
/// from the Identity child <see cref="IServiceProvider"/> into route processors that run inside
/// the host route context. Mirrors the named-instance pattern that <c>RedbRouteExtensions</c>
/// uses for <c>IRedbService</c>:
/// <list type="bullet">
///   <item>Tsak/InitRoute publishes the Identity child SP's <see cref="IServiceScopeFactory"/>
///   in the route-context registry under <c>"identity-sp:{name}"</c>.</item>
///   <item>Per-exchange consumers ask <see cref="GetIdentityService{T}"/> which creates a fresh
///   scope on first call within an exchange and caches it under <c>"__redb_scope:identity-sp:{name}"</c>
///   in <see cref="IExchange.Properties"/>. The scope is auto-disposed by
///   <c>Exchange.ReleaseScopes()</c> alongside named redb scopes (same <c>__redb_scope:</c> prefix
///   is intentional — it co-opts the framework's existing scope-disposal hook so Identity
///   scopes get deterministic cleanup without touching <c>redb.Route</c>).</item>
/// </list>
/// </summary>
/// <remarks>
/// <para>
/// Why this exists: under .tpkg deployment the host root <see cref="IServiceProvider"/> has no
/// Identity registrations — those live in a child container built by
/// <see cref="IdentityModuleHost.Build"/>. <see cref="IExchange.ServiceProvider"/> is a
/// per-exchange scope of the <b>host</b> root, not of the child container, so processors that
/// reach for <c>exchange.ServiceProvider.GetRequiredService&lt;IOpenIddictApplicationManager&gt;()</c>
/// silently work in single-SP test fixtures (Path 1 in <c>InitRoute</c>) yet throw at runtime
/// under tpkg loading (Path 2). Going through this helper unifies both paths.
/// </para>
/// <para>
/// The host SP fallback exists so unit tests that drive a processor without a route context can
/// still resolve services from the host container; production code always hits the registry.
/// </para>
/// </remarks>
public static class IdentityRouteContextExtensions
{
    private const string FactoryPrefix = "identity-sp:";
    // Reuse redb.Route's __redb_scope: prefix so Exchange.ReleaseScopes() auto-disposes
    // Identity scopes — see Exchange.cs:217-233 (named scopes are matched purely by prefix).
    private const string ScopeCachePrefix = "__redb_scope:identity-sp:";
    private const string DefaultName = "default";

    /// <summary>
    /// Publishes the Identity child SP's <see cref="IServiceScopeFactory"/> in the route-context
    /// registry. Call once during module init, after the child SP is built.
    /// </summary>
    public static IRouteContext RegisterIdentityScopeFactory(
        this IRouteContext context,
        string? name,
        IServiceScopeFactory factory)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(factory);
        context.AddToRegistry(FactoryPrefix + Clean(name), factory);
        return context;
    }

    /// <summary>
    /// Resolves <typeparamref name="T"/> from the Identity child container against a per-exchange
    /// scope. Throws if neither the registry factory nor a host SP fallback can satisfy the lookup.
    /// </summary>
    public static T GetIdentityService<T>(
        this IRouteContext context,
        IExchange? exchange,
        string? name = null) where T : notnull
    {
        ArgumentNullException.ThrowIfNull(context);
        var sp = ResolveServiceProvider(context, exchange, name);
        return sp.GetRequiredService<T>();
    }

    /// <summary>
    /// Same as <see cref="GetIdentityService{T}"/> but returns <c>null</c> when the requested
    /// service is not registered. Use for opt-in services like <c>IBackgroundDeletionService</c>
    /// or <c>IRegisteredClientOriginRegistry</c>.
    /// </summary>
    public static T? GetIdentityServiceOrDefault<T>(
        this IRouteContext context,
        IExchange? exchange,
        string? name = null) where T : class
    {
        ArgumentNullException.ThrowIfNull(context);
        var sp = TryResolveServiceProvider(context, exchange, name);
        return sp?.GetService<T>();
    }

    private static IServiceProvider ResolveServiceProvider(IRouteContext context, IExchange? exchange, string? name)
    {
        return TryResolveServiceProvider(context, exchange, name)
            ?? throw new InvalidOperationException(
                $"Identity scope factory '{FactoryPrefix}{Clean(name)}' is not registered, and the route "
                + "context has no fallback IServiceProvider. Ensure InitRoute called "
                + "context.RegisterIdentityScopeFactory(...) during module bootstrap.");
    }

    private static IServiceProvider? TryResolveServiceProvider(IRouteContext context, IExchange? exchange, string? name)
    {
        var clean = Clean(name);

        if (exchange != null)
        {
            var cacheKey = ScopeCachePrefix + clean;

            // Reuse a scope already opened for this exchange (multiple processors in the same
            // pipeline share one Identity scope, mirroring per-exchange IRedbService caching).
            if (exchange.Properties.TryGetValue(cacheKey, out var cached) && cached is IServiceScope cachedScope)
                return cachedScope.ServiceProvider;

            if (context.GetFromRegistry<IServiceScopeFactory>(FactoryPrefix + clean) is { } factory)
            {
                var scope = factory.CreateScope();
                exchange.Properties[cacheKey] = scope;
                return scope.ServiceProvider;
            }

            // Single-SP fallback (unit-test fixtures, legacy hosts that didn't call
            // RegisterIdentityScopeFactory). Still build a per-exchange scope from the host
            // root via the SP's own scope factory, otherwise Scoped services
            // (IOpenIddictApplicationStore = RedbApplicationStore, IRedbService, etc.) get
            // captured at root lifetime and behave as singletons — the per-instance
            // _clientIdCache then persists across all requests and silently shadows DB
            // mutations made through other scopes (see BootstrapAdminEndpointTests where
            // cleanup-scope deletes never reached the captive store's cache, so the
            // bootstrap processor kept finding a stale id=44105488 ghost). Caching the
            // scope on the exchange keeps "same exchange → same scope" for processors that
            // expect shared IRedbService state, matching the factory path above.
            var rootSp = context.GetServiceProvider();
            if (rootSp is not null)
            {
                var rootFactory = rootSp.GetService<IServiceScopeFactory>();
                if (rootFactory is not null)
                {
                    var scope = rootFactory.CreateScope();
                    exchange.Properties[cacheKey] = scope;
                    return scope.ServiceProvider;
                }
                return rootSp;
            }
            return null;
        }

        // No-exchange path (diagnostic tooling that calls into a processor without going
        // through the route system) — return the host root SP as-is. There's no exchange to
        // hang a scope off of, so the caller owns the lifetime.
        return context.GetServiceProvider();
    }

    private static string Clean(string? name) =>
        string.IsNullOrEmpty(name) ? DefaultName : name.TrimStart('#');
}
