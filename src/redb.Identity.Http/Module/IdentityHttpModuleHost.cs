using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using redb.Core;
using redb.Identity.Contracts.Configuration;
using redb.Identity.Contracts.Cors;
using redb.Identity.Contracts.Mfa;
using redb.Identity.DataProtection;
using redb.Identity.Http.Cors;
using redb.Identity.Http.Endpoints;
using redb.Identity.Http.Mfa;
using redb.Identity.Http.Security;
using redb.Route.Abstractions;

namespace redb.Identity.Http.Module;

/// <summary>
/// Builds a self-contained child <see cref="IServiceProvider"/> for the
/// <c>identity.http</c> Tsak context (Phase 9b).
/// <para>
/// Mirrors <c>redb.Identity.Core.Module.IdentityModuleHost</c>: the Tsak.Worker root
/// container is built BEFORE modules are loaded, so all HTTP-facade-internal services
/// (<see cref="SessionTicketService"/>, DataProtection key-ring,
/// <see cref="IOptions{IdentityTransportOptions}"/>) are constructed lazily here from
/// the Tsak-merged config.
/// </para>
/// </summary>
/// <remarks>
/// <para>
/// <b>Bridge services from the host root container:</b>
/// <list type="bullet">
///   <item><see cref="ILoggerFactory"/> — shared logging plumbing.</item>
///   <item><see cref="TimeProvider"/> — testable clock (defaults to system).</item>
///   <item><see cref="IConfiguration"/> — host configuration root.</item>
///   <item><see cref="IRedbService"/> — bridged Scoped via the same
///   <c>HostRedbScope</c> pattern Core uses, so the DataProtection key-ring writes/reads
///   land in the same PROPS store as the rest of Identity.</item>
/// </list>
/// </para>
/// <para>
/// <b>HTTP-facade-owned registrations</b> (built fresh in this child container):
/// <list type="bullet">
///   <item><c>AddDataProtection().PersistKeysToRedb()</c> — cluster-wide key-ring.</item>
///   <item><see cref="SessionTicketService"/> — encrypts session-cookie payloads via
///   the bridged <see cref="IDataProtectionProvider"/>.</item>
///   <item><c>IOptions&lt;IdentityTransportOptions&gt;</c> — bound by
///   <see cref="IdentityHttpConfigBinder"/>.</item>
/// </list>
/// </para>
/// <para>
/// Cross-context state (CORS allowed origins, post-logout-redirect validation, MFA-state
/// inspection) is NOT registered here — it flows through <c>direct-vm://identity-*</c>
/// brokered calls into Core (Phase 9d/9e).
/// </para>
/// </remarks>
internal static class IdentityHttpModuleHost
{
    public static ServiceProvider Build(IRouteContext routeContext, IdentityTransportOptions options)
    {
        ArgumentNullException.ThrowIfNull(routeContext);
        ArgumentNullException.ThrowIfNull(options);

        var rootSp = routeContext.GetServiceProvider()
                     ?? throw new InvalidOperationException(
                         "IRouteContext is missing a backing IServiceProvider — cannot bridge host services.");

        var services = new ServiceCollection();

        // 1. Bridge core host services.
        var loggerFactory = rootSp.GetRequiredService<ILoggerFactory>();
        services.AddSingleton(loggerFactory);
        services.AddLogging();

        services.AddSingleton(rootSp.GetService<TimeProvider>() ?? TimeProvider.System);

        var hostConfiguration = rootSp.GetService<IConfiguration>();
        if (hostConfiguration is not null)
            services.AddSingleton(hostConfiguration);

        // 2. IRedbService — bridged Scoped through a host-side scope, identical pattern to
        //    Core's IdentityModuleHost. The DataProtection IXmlRepository (registered in
        //    step 4 below) opens its own scope per StoreElement call via IServiceScopeFactory,
        //    so we MUST hand it the host-side factory (named instance when configured) and
        //    NOT shadow the child container's own IServiceScopeFactory.
        //
        //    For the HTTP facade the redb instance is selected via the standard Tsak named
        //    redb registry: when the context.json declares Redb:{name}:..., Tsak puts the
        //    scope factory at "redb-factory:{name}". The HTTP facade itself does not own a
        //    RedbInstanceName option (it only needs DataProtection storage); we read it from
        //    a context property "RedbInstanceName" set by the .config.json or fall back to
        //    the default unnamed root provider scope factory.
        var redbInstanceName = routeContext.GetProperty<string?>("RedbInstanceName")?.TrimStart('#');
        IServiceScopeFactory hostRedbScopeFactory;
        if (!string.IsNullOrEmpty(redbInstanceName))
        {
            hostRedbScopeFactory =
                routeContext.GetFromRegistry<IServiceScopeFactory>("redb-factory:" + redbInstanceName)
                ?? throw new InvalidOperationException(
                    $"Named IRedbService '{redbInstanceName}' has no scope factory registered " +
                    $"in the route context (key 'redb-factory:{redbInstanceName}'). Did Tsak's " +
                    "RegisterNamedRedbServices run before module initialisation?");
        }
        else
        {
            hostRedbScopeFactory = rootSp.GetRequiredService<IServiceScopeFactory>();
        }

        var hostScopeFactoryHolder = new HostRedbScopeFactoryHolder(hostRedbScopeFactory);
        services.AddSingleton(hostScopeFactoryHolder);
        services.AddScoped<HostRedbScope>();
        services.AddScoped<IRedbService>(sp => sp.GetRequiredService<HostRedbScope>().Service);

        // 3. Options snapshot.
        services.AddSingleton(Options.Create(options));
        services.AddOptions();

        // 4. DataProtection key-ring backed by redb PROPS (Phase 9a shared project).
        //    SetApplicationName must match Core's value so both contexts (and any other
        //    facades) use the same purpose-string namespace and can decrypt each other's
        //    payloads — required for the session ticket / federation state cookie story.
        services.AddDataProtection()
            .SetApplicationName("redb.identity")
            .PersistKeysToRedb();

        // 5. HTTP-facade-owned services.
        services.AddSingleton<SessionTicketService>();

        // 6. Phase 9e — cross-context broker bridges. The HTTP facade has no
        //    project-reference on Core, so the «is this Origin allowed for CORS?»,
        //    «is this post-logout-redirect URI registered?» and «what MFA methods does
        //    this state token carry?» queries are issued via direct-vm:// to Core's
        //    matching processors (registered in IdentityCoreRouteBuilder, see Phase 9d).
        //    The brokered impls take IRouteContext (NOT IServiceProvider) — that is
        //    the only object that can resolve direct-vm endpoints in the SharedVmRegistry.
        services.AddSingleton(routeContext);
        services.AddSingleton<IRegisteredClientOriginRegistry>(sp =>
            new BrokeredRegisteredClientOriginRegistry(sp.GetRequiredService<IRouteContext>()));
        services.AddSingleton<IMfaStateInspector>(sp =>
            new BrokeredMfaStateInspector(sp.GetRequiredService<IRouteContext>()));
        services.AddSingleton(sp =>
            new BrokeredPostLogoutRedirectValidator(sp.GetRequiredService<IRouteContext>()));

        // E7: enforce captive-dependency detection at build time.
        return services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateScopes = true,
            ValidateOnBuild = true,
        });
    }
}

/// <summary>
/// Disposes the HTTP-facade child <see cref="IServiceProvider"/> when the surrounding
/// route context stops. Without this the child container would leak across Tsak hot-reloads.
/// </summary>
internal sealed class HttpChildHostDisposeListener : IRouteLifecycleListener
{
    private readonly ServiceProvider _childSp;

    public HttpChildHostDisposeListener(ServiceProvider childSp) => _childSp = childSp;

    public Task OnContextStopped(IRouteContext context, CancellationToken ct)
    {
        _childSp.Dispose();
        return Task.CompletedTask;
    }
}

/// <summary>
/// Per-child-scope wrapper around a host-side <see cref="IServiceScope"/> that exposes
/// <see cref="IRedbService"/> with deterministic disposal — identical pattern to
/// <c>redb.Identity.Core.Module.HostRedbScope</c>. Required so the redb-backed
/// DataProtection repository never captive-captures a Scoped <see cref="IRedbService"/>.
/// </summary>
internal sealed class HostRedbScope : IDisposable, IAsyncDisposable
{
    private readonly IServiceScope _hostScope;
    public IRedbService Service { get; }

    public HostRedbScope(HostRedbScopeFactoryHolder holder)
    {
        _hostScope = holder.Factory.CreateScope();
        Service = _hostScope.ServiceProvider.GetRequiredService<IRedbService>();
    }

    public void Dispose() => _hostScope.Dispose();

    public ValueTask DisposeAsync() =>
        _hostScope is IAsyncDisposable a ? a.DisposeAsync() : new ValueTask(Task.Run(_hostScope.Dispose));
}

/// <summary>
/// Marker holder for the host's <see cref="IServiceScopeFactory"/>. Registered as a
/// distinct type (NOT as <see cref="IServiceScopeFactory"/> directly) so the child
/// container keeps its own scope factory intact while still being able to reach the
/// host one when bridging <see cref="IRedbService"/>.
/// </summary>
internal sealed class HostRedbScopeFactoryHolder
{
    public IServiceScopeFactory Factory { get; }
    public HostRedbScopeFactoryHolder(IServiceScopeFactory factory) => Factory = factory;
}
