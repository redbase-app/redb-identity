using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using redb.Route.Abstractions;

namespace redb.Identity.Grpc.Module;

/// <summary>
/// Builds a self-contained child <see cref="IServiceProvider"/> for the <c>identity.grpc</c> Tsak
/// context. Mirrors <c>redb.Identity.Http.Module.IdentityHttpModuleHost</c>: the worker's root container
/// is built before modules load, so facade-owned services are constructed lazily here from the
/// Tsak-merged config.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately much smaller than the HTTP host. The gRPC facade serves no browser flows, so it owns no
/// cookies, no DataProtection key-ring and no page state — and therefore needs no bridged
/// <c>IRedbService</c>. Everything stateful stays in Core and is reached over <c>direct-vm://</c>.
/// </para>
/// <para>
/// Registered here: the host logger factory and clock, the host configuration root (when present), the
/// bound <see cref="IdentityGrpcTransportOptions"/>, and the <see cref="IRouteContext"/> itself — the
/// latter is the only object able to resolve <c>direct-vm</c> endpoints through the shared registry, so
/// brokered calls into Core take it rather than an <see cref="IServiceProvider"/>.
/// </para>
/// </remarks>
internal static class IdentityGrpcModuleHost
{
    public static ServiceProvider Build(IRouteContext routeContext, IdentityGrpcTransportOptions options)
    {
        ArgumentNullException.ThrowIfNull(routeContext);
        ArgumentNullException.ThrowIfNull(options);

        var rootSp = routeContext.GetServiceProvider()
                     ?? throw new InvalidOperationException(
                         "IRouteContext is missing a backing IServiceProvider — cannot bridge host services.");

        var services = new ServiceCollection();

        services.AddSingleton(rootSp.GetRequiredService<ILoggerFactory>());
        services.AddLogging();
        services.AddSingleton(rootSp.GetService<TimeProvider>() ?? TimeProvider.System);

        var hostConfiguration = rootSp.GetService<IConfiguration>();
        if (hostConfiguration is not null)
            services.AddSingleton(hostConfiguration);

        services.AddSingleton(Options.Create(options));
        services.AddOptions();

        // Brokered calls into Core go through the route context, not through DI.
        services.AddSingleton(routeContext);

        // Captive-dependency detection at build time, same as the HTTP facade.
        return services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateScopes = true,
            ValidateOnBuild = true,
        });
    }
}

/// <summary>
/// Disposes the gRPC-facade child container when the surrounding route context stops. Without it the
/// container would leak across Tsak hot-reloads.
/// </summary>
internal sealed class GrpcChildHostDisposeListener : IRouteLifecycleListener
{
    private readonly ServiceProvider _childSp;

    public GrpcChildHostDisposeListener(ServiceProvider childSp) => _childSp = childSp;

    public Task OnContextStopped(IRouteContext context, CancellationToken ct)
    {
        _childSp.Dispose();
        return Task.CompletedTask;
    }
}
