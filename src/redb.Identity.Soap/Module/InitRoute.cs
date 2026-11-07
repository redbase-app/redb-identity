using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using redb.Identity.Soap.Module;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.Soap;

// Tsak resolves the {Module}.config.json file by InitRoute's namespace
// (TsakModuleRegistry.DiscoverModulesInAssembly). Keep this namespace aligned with the shipped config
// filename `redb.Identity.Soap.config.json`.
//
// This module owns ContextName "identity.soap" — its own RouteContext, separate from Core ("identity"),
// the HTTP facade ("identity.http") and the gRPC facade ("identity.grpc"). They communicate exclusively
// through `direct-vm://identity-*` brokered messages whose DTOs live in redb.Identity.Contracts; this
// facade has zero project-reference on Core (Phase 8 invariant).
namespace redb.Identity.Soap;

/// <summary>
/// Tsak module entry point for the WS-Trust facade. Discovered by convention: public class InitRoute with
/// a static main(IRouteContext).
/// </summary>
public static class InitRoute
{
    public static IRouteContext main(IRouteContext context)
    {
        // The SOAP component serves on the shared Kestrel host, the same one Http, As2 and Grpc use, so a
        // WS-Trust route and an HTTP route in one worker never fight over a port.
        if (!context.HasComponent("soap"))
            context.AddComponent(new SoapComponent());

        // Two boot paths, mirroring Core and the other facades:
        //   1. Test fixtures / programmatic embedding — the host pre-registers
        //      IConfigureOptions<IdentitySoapTransportOptions> on the root container.
        //   2. Tsak.Worker .tpkg loading — the host root knows nothing about this facade, so the binder
        //      reads "IdentityTransport" from the merged context configuration and the module host builds
        //      a child ServiceProvider.
        var hostSp = context.GetServiceProvider()
                     ?? throw new InvalidOperationException(
                         "IServiceProvider not available on IRouteContext. " +
                         "Ensure the Identity SOAP module is loaded after DI is configured.");

        var hostHasSoap = hostSp.GetServices<IConfigureOptions<IdentitySoapTransportOptions>>().Any();

        IServiceProvider soapSp;
        if (hostHasSoap)
        {
            soapSp = hostSp;
        }
        else
        {
            var bound = IdentitySoapConfigBinder.Bind(context);
            var childSp = IdentitySoapModuleHost.Build(context, bound);
            // Ensure the child container outlives the routes but dies with the context.
            context.AddLifecycleListener(new SoapChildHostDisposeListener(childSp));
            soapSp = childSp;
        }

        var options = soapSp.GetRequiredService<IOptions<IdentitySoapTransportOptions>>();

        var logger = (soapSp.GetService<ILoggerFactory>() ?? hostSp.GetService<ILoggerFactory>())
            ?.CreateLogger("redb.Identity.Soap.InitRoute");

        var soap = options.Value.Soap;
        logger?.LogInformation(
            "[Identity.Soap.InitRoute] Building WS-Trust facade routes on {Host}:{Port}{Path} (TLS: {Ssl}, WSDL: {Wsdl})",
            soap.Host, soap.Port, soap.Path, soap.Ssl, soap.Wsdl);

        var routeContext = (RouteContext)context;
        routeContext.AddRoutes(new SoapFacadeRouteBuilder(options));

        // One route, by design: WS-Trust puts Issue, Validate, Cancel and Renew on a single address and
        // tells them apart by the WS-Addressing Action. The endpoint count in the worker log is therefore
        // 1 for this module, and that is what «loaded correctly» looks like here — unlike the gRPC facade,
        // where the same counter is what revealed a module registering half of itself.
        return context;
    }
}
