using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Module;
using redb.Identity.Core.Routes;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.Redis;

// Tsak determines the module name from the namespace of the InitRoute class
// (TsakModuleRegistry.DiscoverModulesInAssembly). The configuration file Tsak then
// looks for is "{Namespace}.config.json" → "redb.Identity.Core.config.json".
namespace redb.Identity.Core;

/// <summary>
/// Tsak module entry point for redb.Identity.Core.
/// Registers <see cref="IdentityCoreRouteBuilder"/> (13+ direct-vm:// routes) in the route context.
/// Discovered by convention: public class InitRoute with static main(IRouteContext).
/// </summary>
/// <remarks>
/// Two boot paths are supported:
/// <list type="number">
///   <item><b>Test fixtures / programmatic embedding</b> — host pre-registers
///   <see cref="RedbIdentityOptions"/> via <c>services.AddRedbIdentityServer(...)</c>
///   on the root container. Detected by the presence of
///   <c>IOptions&lt;RedbIdentityOptions&gt;</c> in the host service provider.</item>
///   <item><b>Tsak.Worker .tpkg loading</b> — host root container has no Identity
///   knowledge. <see cref="IdentityModuleConfigBinder"/> reads
///   <c>"Identity"</c> from the merged Tsak context configuration and
///   <see cref="IdentityModuleHost"/> builds a child <see cref="ServiceProvider"/>
///   that owns all Identity services. The child is disposed automatically on context
///   stop via <see cref="ChildHostDisposeListener"/>.</item>
/// </list>
/// </remarks>
public static class InitRoute
{
    public static IRouteContext main(IRouteContext context)
    {
        var hostSp = context.GetServiceProvider()
                     ?? throw new InvalidOperationException(
                         "IServiceProvider not available on IRouteContext. " +
                         "Ensure the Identity Core module is loaded after DI is configured.");

        // Path 1: host pre-registered RedbIdentityOptions (existing test/embed path).
        // Path 2: self-bootstrap from Tsak {Module}.config.json (.tpkg path).
        //
        // We CANNOT detect Path 1 by `hostSp.GetService<IOptions<RedbIdentityOptions>>()`:
        // IOptions<T> is *always* resolvable from any container with `AddOptions()`
        // wired (Tsak does this) — it returns a default-constructed `new RedbIdentityOptions()`
        // even when nobody called `services.Configure<RedbIdentityOptions>()`. The proper
        // signal is the presence of an IConfigureOptions<RedbIdentityOptions> registration,
        // which only `services.AddRedbIdentityServer(...)` (or an explicit `Configure`) emits.
        var hostHasIdentity = hostSp.GetServices<IConfigureOptions<RedbIdentityOptions>>().Any();
        IServiceProvider identitySp;
        IOptions<RedbIdentityOptions> options;

        if (hostHasIdentity)
        {
            identitySp = hostSp;
            options = hostSp.GetRequiredService<IOptions<RedbIdentityOptions>>();
        }
        else
        {
            var bound = IdentityModuleConfigBinder.Bind(context);
            var childSp = IdentityModuleHost.Build(context, bound);
            // Ensure the child container outlives the routes but dies with the context.
            context.AddLifecycleListener(new ChildHostDisposeListener(childSp));
            identitySp = childSp;
            options = childSp.GetRequiredService<IOptions<RedbIdentityOptions>>();
        }

        // Initialize redb base schema BEFORE any route starts processing exchanges.
        // Per-Props schemas register lazily on first Query/Save.
        context.AddLifecycleListener(new IdentitySchemaInitListener(identitySp));

        // After the base schema is live, create per-scheme partial unique indexes that
        // close TOCTOU races in check-then-save paths (ClientId, Scope.Name, MFA user,
        // idempotency keys, OIDC-extension user). Registered AFTER the schema listener
        // so it can look up scheme ids against an already-bootstrapped database.
        context.AddLifecycleListener(new IdentityUniqueIndexesInitListener(identitySp));

        // Audit log: ensure the flat relational table that backs
        // /api/v1/identity/audit exists. Idempotent CREATE IF NOT EXISTS per
        // dialect (Postgres / MSSQL / SQLite) shipped as embedded DDL.
        context.AddLifecycleListener(new IdentityAuditLogTableInitListener(identitySp));

        // B.3: seed canonical built-in roles so /admin/roles isn't empty
        // on a fresh install. Idempotent.
        context.AddLifecycleListener(new SeedSystemRolesListener(identitySp));

        // B.3: seed the static IdentityScopes catalogue so the role-
        // permissions picker on /admin/roles/{id} can search and attach
        // admin scopes. Without this only operator-created scopes show up.
        context.AddLifecycleListener(new SeedSystemScopesListener(identitySp));

        // B.3 backfill: mirror bootstrap admin-group members into the admin
        // role for installs created BEFORE the system-roles registry landed.
        // Idempotent. Runs after SeedSystemRolesListener so it sees the
        // freshly created role on first boot.
        context.AddLifecycleListener(new BootstrapAdminBackfillListener(identitySp));

        // B.3 SQL-seed bridge: assign the canonical SeedAdmin user (the
        // 'admin' account from the redb SQL seed) directly to the admin
        // system role. Closes the gap between the SQL seed and the role
        // registry — without this listener installs that never call
        // /internal/bootstrap-admin leave the admin role with zero
        // assignees. Idempotent.
        context.AddLifecycleListener(new SeedAdminRoleAssignmentListener(identitySp,
            identitySp.GetRequiredService<IOptions<RedbIdentityOptions>>()));

        // Seed the DataProtection key-ring snapshot BEFORE the HTTP facade serves the first
        // request — prevents Protect/Unprotect from racing against an empty in-memory ring.
        context.AddLifecycleListener(new RedbXmlRepositoryInitListener(identitySp));

        // A3: seed the PROPS signing / encryption key store AFTER the DataProtection key ring
        // has been loaded (PROPS rows store DataProtection-encrypted PEMs). No-op when
        // RedbIdentityOptions.UsePropsSigningKeyStore=false.
        context.AddLifecycleListener(new SigningKeyInitListener(identitySp));

        // C1: When the Redis-backed rate-limit store is enabled, register the redis
        // component once (idempotent — overwrites by scheme key) so other parts of the
        // route system can also resolve redis: URIs against the same broker. Mirrors the
        // demo pattern of adding components inside InitRoute rather than expecting the
        // host to do it.
        if (options.Value.RateLimit.Enabled
            && string.Equals(options.Value.RateLimit.Backend, "redis", StringComparison.OrdinalIgnoreCase))
        {
            context.AddComponent(new RedisComponent());
        }

        // W1: outbound HTTP transport for webhook delivery. Producer-only —
        // ServerManager intentionally omitted (this context never hosts an
        // HTTP server; that's the Http facade module's job). Without this
        // registration, ProducerTemplate.SendAsync to https://... URIs fails
        // with 'No component registered for scheme http'. Adding it locally
        // keeps Core transport-agnostic at the SCHEMA level (subscription.Url
        // is still opaque) while owning the producer-side resolution for the
        // schemes Core actively delivers to.
        if (!context.HasComponent("http"))
            context.AddComponent(new redb.Route.Http.HttpComponent());
        if (!context.HasComponent("https"))
            context.AddComponent(new redb.Route.Http.HttpComponent("https"));

        var builder = new IdentityCoreRouteBuilder(identitySp, options);
        ((RouteContext)context).AddRoutes(builder);

        return context;
    }
}
