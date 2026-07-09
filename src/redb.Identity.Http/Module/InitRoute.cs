using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using redb.Identity.Http.Module;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.Http;

// Tsak resolves the {Module}.config.json file by InitRoute's namespace
// (TsakModuleRegistry.DiscoverModulesInAssembly). Keep this namespace aligned
// with the shipped config filename `redb.Identity.Http.config.json`.
//
// Phase 8/9: this module owns ContextName "identity.http" — a separate RouteContext
// from redb.Identity.Core ("identity"). The two communicate exclusively through
// `direct-vm://identity-*` brokered messages whose DTOs live in
// redb.Identity.Contracts. The Http facade has zero project-reference on Core.
//
// Phase 9b: Http now builds its OWN child IServiceProvider via IdentityHttpModuleHost
// (mirrors Core's IdentityModuleHost). The child SP owns SessionTicketService, the
// DataProtection key-ring (PersistKeysToRedb, shared cluster-wide) and IdentityTransport
// options. Cross-context state (CORS allowed origins, post-logout-redirect validation,
// MFA-state inspection) is fetched on-demand via direct-vm:// calls into Core (Phase 9d/9e).
namespace redb.Identity.Http;

/// <summary>
/// Tsak module entry point. Builds the HTTP-facade child container and registers
/// <see cref="HttpFacadeRouteBuilder"/> in the route context.
/// Discovered by convention: public class InitRoute with static main(IRouteContext).
/// </summary>
public static class InitRoute
{
    public static IRouteContext main(IRouteContext context)
    {
        // Ensure HttpComponent is registered (may already be by another module).
        if (!context.HasComponent("http"))
        {
            context.AddComponent(new HttpComponent
            {
                ServerManager = new SharedHttpServerManager()
            });
        }

        // Two boot paths (mirrors Core's InitRoute):
        //   1. Test fixtures / programmatic embedding — host pre-registers
        //      IdentityTransportOptions + SessionTicketService on the root container.
        //      Detected by the presence of an IConfigureOptions<IdentityTransportOptions>
        //      registration on the host SP.
        //   2. Tsak.Worker .tpkg loading — host root has no Identity-Http knowledge.
        //      IdentityHttpConfigBinder reads "IdentityTransport" from the merged
        //      Tsak context configuration and IdentityHttpModuleHost builds a child
        //      ServiceProvider that owns all HTTP-facade services.
        var hostSp = context.GetServiceProvider()
                     ?? throw new InvalidOperationException(
                         "IServiceProvider not available on IRouteContext. " +
                         "Ensure the Identity HTTP module is loaded after DI is configured.");

        var hostHasHttp = hostSp
            .GetServices<IConfigureOptions<redb.Identity.Http.IdentityTransportOptions>>()
            .Any();
        IServiceProvider httpSp;

        if (hostHasHttp)
        {
            httpSp = hostSp;
        }
        else
        {
            var bound = IdentityHttpConfigBinder.Bind(context);
            var childSp = IdentityHttpModuleHost.Build(context, bound);
            // Ensure the child container outlives the routes but dies with the context.
            context.AddLifecycleListener(new HttpChildHostDisposeListener(childSp));
            httpSp = childSp;
        }

        // Seed the DataProtection key-ring snapshot BEFORE the HTTP facade serves the
        // first request. Without this, the very first session-cookie Unprotect would
        // race against an empty in-memory ring and force KeyManager to mint a fresh key
        // — invalidating any previously issued cookies.
        context.AddLifecycleListener(new IdentityHttpXmlRepositoryInitListener(httpSp));

        // Phase 9b (clean rewire): bearer-auth is now invoked via
        // `direct-vm://identity-auth-{management,scim}`. Core publishes the consumer,
        // this facade calls it inline with `.To(...)` — no cross-module static state.

        var initLogger = (httpSp.GetService<Microsoft.Extensions.Logging.ILoggerFactory>()
                          ?? hostSp.GetService<Microsoft.Extensions.Logging.ILoggerFactory>())
                         ?.CreateLogger("redb.Identity.Http.InitRoute");
        initLogger?.LogInformation("[Identity.Http.InitRoute] Building HTTP facade routes");

        var builder = new HttpFacadeRouteBuilder(
            httpSp.GetRequiredService<redb.Identity.Http.Security.SessionTicketService>(),
            httpSp.GetRequiredService<IOptions<IdentityTransportOptions>>(),
            httpSp.GetService<redb.Identity.Http.Endpoints.BrokeredPostLogoutRedirectValidator>(),
            httpSp.GetService<redb.Identity.Contracts.Mfa.IMfaStateInspector>(),
            httpSp.GetService<redb.Identity.Contracts.Cors.IRegisteredClientOriginRegistry>());
        ((RouteContext)context).AddRoutes(builder);

        return context;
    }
}
