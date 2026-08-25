using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using redb.Identity.Grpc.Module;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.Grpc;

// Tsak resolves the {Module}.config.json file by InitRoute's namespace
// (TsakModuleRegistry.DiscoverModulesInAssembly). Keep this namespace aligned with the shipped config
// filename `redb.Identity.Grpc.config.json`.
//
// This module owns ContextName "identity.grpc" — its own RouteContext, separate from Core ("identity")
// and from the HTTP facade ("identity.http"). The three communicate exclusively through
// `direct-vm://identity-*` brokered messages whose DTOs live in redb.Identity.Contracts; this facade has
// zero project-reference on Core (Phase 8 invariant).
namespace redb.Identity.Grpc;

/// <summary>
/// Tsak module entry point for the gRPC facade. Discovered by convention: public class InitRoute with a
/// static main(IRouteContext).
/// </summary>
public static class InitRoute
{
    public static IRouteContext main(IRouteContext context)
    {
        // The gRPC component serves on the shared Kestrel host, the same one Http, As2 and Soap use, so a
        // gRPC route and an HTTP route in one worker never fight over a port. AddRedbRouteGrpc() would do
        // this via DI, but a Tsak module gets a context, not a service collection — so wire it by hand and
        // let the component fall back to the host's shared manager when one is registered.
        if (!context.HasComponent("grpc"))
            context.AddComponent(new GrpcComponent());

        // Two boot paths, mirroring Core and the HTTP facade:
        //   1. Test fixtures / programmatic embedding — the host pre-registers
        //      IConfigureOptions<IdentityGrpcTransportOptions> on the root container.
        //   2. Tsak.Worker .tpkg loading — the host root knows nothing about this facade, so the binder
        //      reads "IdentityTransport" from the merged context configuration and the module host builds
        //      a child ServiceProvider.
        var hostSp = context.GetServiceProvider()
                     ?? throw new InvalidOperationException(
                         "IServiceProvider not available on IRouteContext. " +
                         "Ensure the Identity gRPC module is loaded after DI is configured.");

        var hostHasGrpc = hostSp.GetServices<IConfigureOptions<IdentityGrpcTransportOptions>>().Any();

        IServiceProvider grpcSp;
        if (hostHasGrpc)
        {
            grpcSp = hostSp;
        }
        else
        {
            var bound = IdentityGrpcConfigBinder.Bind(context);
            var childSp = IdentityGrpcModuleHost.Build(context, bound);
            // Ensure the child container outlives the routes but dies with the context.
            context.AddLifecycleListener(new GrpcChildHostDisposeListener(childSp));
            grpcSp = childSp;
        }

        var options = grpcSp.GetRequiredService<IOptions<IdentityGrpcTransportOptions>>();

        var logger = (grpcSp.GetService<ILoggerFactory>() ?? hostSp.GetService<ILoggerFactory>())
            ?.CreateLogger("redb.Identity.Grpc.InitRoute");

        var grpc = options.Value.Grpc;
        logger?.LogInformation(
            "[Identity.Grpc.InitRoute] Building gRPC facade routes on {Host}:{Public} (management: {Management})",
            grpc.Host, grpc.PublicPort, grpc.EffectiveManagementPort);

        var routeContext = (RouteContext)context;

        // The protocol surface: token, introspect, revoke, userinfo, discovery, jwks, plus the envelope.
        routeContext.AddRoutes(new GrpcFacadeRouteBuilder(options));

        // The management surface. Registered here and not only in tests: without this line the forty admin
        // operations exist, are covered, and are unreachable in every real deployment — while the log line
        // above still announces a management port, so it reads as configured. A live worker showed
        // `identity.grpc` starting with 7 endpoints instead of 47, which is how this was found.
        routeContext.AddRoutes(new GrpcManagementRouteBuilder(options));

        return context;
    }
}
