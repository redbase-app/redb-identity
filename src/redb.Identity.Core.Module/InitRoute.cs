using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using redb.Identity.Core;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Module;
using redb.Identity.Contracts.Routes;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.Redis;
using redb.Identity.Core.Routes;
using OpenIddict.Validation;

// ─── Tsak module discovery contract ──────────────────────────────────────────
//
// Tsak determines the moduleName from the namespace of the discovered InitRoute
// class (TsakModuleRegistry.DiscoverModulesInAssembly). This namespace MUST stay
// in sync with:
//   • The .tpkg manifest.Name                          → "redb.Identity.Core.Module"
//   • The shipped {moduleName}.config.json filename    → "redb.Identity.Core.Module.config.json"
//   • The Dependencies declared by every facade .tpkg  (Http, gRPC, MQTT, …) so
//     Tsak loads this package first and the companion DLLs (Identity.Core,
//     Identity.Contracts, OpenIddict, Argon2, Fido2, …) are present in the
//     LoadedAssemblyTracker before any facade ALC tries to resolve them.
//
// ─── Why this assembly is *thin* ─────────────────────────────────────────────
//
// Tsak loads `manifest.EntryPoints` into a per-package isolated ALC and does
// NOT register them in `LoadedAssemblyTracker` (entry points are deliberately
// hidden from sibling .tpkg packages). Companion DLLs in the .tpkg ARE tracked
// and shared by Assembly identity across every ALC that resolves them.
//
// If we shipped redb.Identity.Core.dll itself as the entry point (as the
// original prototype did), no other .tpkg facade could resolve its types ─
// HttpFacadeRouteBuilder's ctor would throw FileNotFoundException for
// redb.Identity.Core. Splitting the entry point into this tiny shim makes
// Identity.Core.dll, Identity.Contracts.dll and every transitive NuGet dep
// COMPANION DLLs that other .tpkg packages can rely on.
namespace redb.Identity.Core.Module;

/// <summary>
/// Tsak module entry point for redb.Identity.Core.Module.
/// Wires the lifecycle listeners that bootstrap the Identity DI/redb schema/key
/// ring and registers <see cref="IdentityCoreRouteBuilder"/>'s direct-vm:// routes.
/// Discovered by convention: <c>public class InitRoute</c> with
/// <c>static main(IRouteContext)</c>.
/// </summary>
/// <remarks>
/// Two boot paths are supported (unchanged from the original Core entry point):
/// <list type="number">
///   <item><b>Test fixtures / programmatic embedding</b> — host pre-registers
///   <see cref="RedbIdentityOptions"/> via <c>services.AddRedbIdentityServer(...)</c>
///   on the root container. Detected by the presence of an
///   <see cref="IConfigureOptions{RedbIdentityOptions}"/> registration on the
///   host service provider (NOT <see cref="IOptions{RedbIdentityOptions}"/> —
///   that is always resolvable when <c>AddOptions()</c> is wired and would yield
///   a default-constructed instance under .tpkg loading).</item>
///   <item><b>Tsak.Worker .tpkg loading</b> — host root container has no
///   Identity knowledge. <see cref="IdentityModuleConfigBinder"/> reads
///   <c>"Identity"</c> from the merged Tsak context configuration and
///   <see cref="IdentityModuleHost"/> builds a child <see cref="ServiceProvider"/>
///   that owns all Identity services. The child is disposed automatically on
///   context stop via <see cref="ChildHostDisposeListener"/>.</item>
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

        // Path 1 vs Path 2 detection — see remarks above.
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
            var ldap = LdapIntegrationConfigBinder.Bind(context);
            var childSp = IdentityModuleHost.Build(context, bound, services =>
            {
                if (ldap is { Enabled: true, Providers.Count: > 0 })
                {
                    foreach (var provider in ldap.Providers)
                        redb.Identity.Ldap.LdapServiceExtensions.AddRedbIdentityLdap(services, provider);
                }
            });
            // Ensure the child container outlives the routes but dies with the context.
            context.AddLifecycleListener(new ChildHostDisposeListener(childSp));
            identitySp = childSp;
            options = childSp.GetRequiredService<IOptions<RedbIdentityOptions>>();
        }

        // Publish the Identity SP's IServiceScopeFactory so route processors can resolve
        // child-SP services (IOpenIddictApplicationManager, IBackgroundDeletionService, …)
        // against per-exchange scopes via IRouteContext.GetIdentityService<T>(exchange).
        // Path 1 (test fixture): identitySp == hostSp, factory creates scopes on the host SP.
        // Path 2 (tpkg): identitySp is the Identity child container, factory bridges into it.
        context.RegisterIdentityScopeFactory(
            name: null,
            identitySp.GetRequiredService<IServiceScopeFactory>());

        // Initialize redb base schema BEFORE any route starts processing exchanges.
        // Per-Props schemas register lazily on first Query/Save.
        context.AddLifecycleListener(new IdentitySchemaInitListener(identitySp));

        // After the base schema is live, create per-scheme partial unique indexes that
        // close TOCTOU races in check-then-save paths (ClientId, Scope.Name, MFA user,
        // idempotency keys, OIDC-extension user). Registered AFTER the schema listener
        // so it can look up scheme ids against an already-bootstrapped database.
        context.AddLifecycleListener(new IdentityUniqueIndexesInitListener(identitySp));

        // R1: audit log relational table — flat schema for the
        // `identity_audit_log` table that backs /api/v1/identity/audit and
        // the user-detail Audit tab. Idempotent CREATE IF NOT EXISTS per
        // dialect (Postgres / MSSQL / SQLite) shipped as embedded DDL.
        context.AddLifecycleListener(new IdentityAuditLogTableInitListener(identitySp));

        // B.3: seed the canonical built-in roles (system / everyone / admin /
        // impersonator) so /admin/roles isn't empty on a fresh install.
        // Idempotent — skips existing rows by name+audience.
        context.AddLifecycleListener(new SeedSystemRolesListener(identitySp));

        // B.3: seed the IdentityScopes catalogue so the role-permissions
        // picker can find / attach built-in admin scopes
        // (identity:users.manage, identity:applications.manage, …). Idempotent.
        context.AddLifecycleListener(new SeedSystemScopesListener(identitySp));

        // B.3 backfill: mirror bootstrap admin-group members into the admin
        // role for installs created BEFORE the system-roles registry landed.
        // Idempotent. Runs after SeedSystemRolesListener so it sees the role.
        context.AddLifecycleListener(new BootstrapAdminBackfillListener(identitySp));

        // B.3 SQL-seed bridge: assign the canonical SeedAdmin user to the
        // admin system role directly. Without this, installs that never
        // call /internal/bootstrap-admin leave the admin role empty.
        context.AddLifecycleListener(new SeedAdminRoleAssignmentListener(identitySp,
            identitySp.GetRequiredService<IOptions<RedbIdentityOptions>>()));

        // Seed the DataProtection key-ring snapshot BEFORE the HTTP facade serves the
        // first request — prevents Protect/Unprotect from racing against an empty
        // in-memory ring.
        context.AddLifecycleListener(new RedbXmlRepositoryInitListener(identitySp));

        // A3: seed the PROPS signing / encryption key store AFTER the DataProtection key
        // ring has been loaded (PROPS rows store DataProtection-encrypted PEMs). No-op
        // when RedbIdentityOptions.UsePropsSigningKeyStore=false.
        context.AddLifecycleListener(new SigningKeyInitListener(identitySp));

        // Default-credential seeders. Both run on every cold-start AND every hot-reload
        // (Tsak invokes OnContextStarting for the listeners on each module init), are
        // fully idempotent, and never fail host startup. Order matters: schema must be
        // live before either runs (admin password write → _users; OIDC client write →
        // OpenIddict PROPS tables), so they are appended LAST in the listener chain.
        context.AddLifecycleListener(
            identitySp.GetRequiredService<redb.Identity.Core.Services.SeedAdminPasswordHostedService>());
        context.AddLifecycleListener(
            identitySp.GetRequiredService<redb.Identity.Core.Services.SeedWebClientHostedService>());
        context.AddLifecycleListener(
            identitySp.GetRequiredService<redb.Identity.Core.Services.SeedBackchannelClientHostedService>());

        // C1: When the Redis-backed rate-limit store is enabled, register the redis
        // component once (idempotent — overwrites by scheme key) so other parts of the
        // route system can also resolve redis: URIs against the same broker.
        if (options.Value.RateLimit.Enabled
            && string.Equals(options.Value.RateLimit.Backend, "redis", StringComparison.OrdinalIgnoreCase))
        {
            context.AddComponent(new RedisComponent());
        }

        // W1: outbound HTTP transport for webhook delivery. Producer-only —
        // no ServerManager (this Core context never hosts an HTTP server; the
        // Http facade module owns that). Without this registration,
        // ProducerTemplate.SendAsync to https://... URIs fails with
        // 'No component registered for scheme http'.
        if (!context.HasComponent("http"))
            context.AddComponent(new redb.Route.Http.HttpComponent());
        if (!context.HasComponent("https"))
            context.AddComponent(new redb.Route.Http.HttpComponent("https"));

        // Phase 9b (clean rewire): construct the management/SCIM bearer-auth
        // processors inside Core's child SP and pass them to the route builder, which
        // exposes them as `direct-vm://identity-auth-{management,scim}` consumers.
        // The HTTP facade module then calls them inline via `.To(...)` — no static
        // cross-module state, no per-context registry handoff. The processors depend
        // on scoped OpenIddict validation services, so we keep a long-lived scope
        // tied to the route context lifetime (BridgeScopeDisposeListener).
        var bridgeLogger = (identitySp.GetService<Microsoft.Extensions.Logging.ILoggerFactory>()
                            ?? hostSp.GetService<Microsoft.Extensions.Logging.ILoggerFactory>())
                          ?.CreateLogger("redb.Identity.Core.InitRoute");
        IProcessor? managementAuth = null;
        IProcessor? scimAuth = null;
        try
        {
            var bridgeScope = identitySp.CreateScope();
            context.AddLifecycleListener(new BridgeScopeDisposeListener(bridgeScope));

            var validationFactory = bridgeScope.ServiceProvider.GetRequiredService<IOpenIddictValidationFactory>();
            var validationDispatcher = bridgeScope.ServiceProvider.GetRequiredService<IOpenIddictValidationDispatcher>();
            var opts = options.Value;

            managementAuth = new redb.Identity.Core.Routes.Processors.ManagementBearerAuthProcessor(
                validationFactory, validationDispatcher,
                // N7-1 — accept all granular admin scopes here. The per-path
                // GranularScopeGuardProcessor (HTTP facade) then enforces which
                // route a given granular scope may reach. Manage remains the
                // master scope and AccountScope still routes to self-service.
                BuildAcceptableManagementScopes(opts),
                // N-4 (Session C): password-recovery flows are genuinely anonymous and
                // share the /api/v1/identity/ root for URL stability. The auth processor
                // short-circuits without reading the Authorization header for these paths.
                // RFC 7644 §4: SCIM discovery endpoints (ServiceProviderConfig, ResourceTypes,
                // Schemas) must be unauthenticated; they are accessible under /api/v1/identity/scim/v2/*.
                anonymousPathPrefixes: new[] {
                    "/api/v1/identity/password/",
                    "/api/v1/identity/account/",
                    "/api/v1/identity/federation-providers/public",
                    "/api/v1/identity/scim/v2/ServiceProviderConfig",
                    "/api/v1/identity/scim/v2/ResourceTypes",
                    "/api/v1/identity/scim/v2/Schemas"
                });
            bridgeLogger?.LogInformation(
                "[Identity.Core.InitRoute] Built ManagementAuth processor (scopes=[{Mgmt},{Account},+{Granular} granular])",
                opts.ManagementScope, opts.AccountScope,
                redb.Identity.Contracts.Configuration.IdentityScopes.GranularAdmin.Length);

            if (opts.Features.EnableScim)
            {
                scimAuth = new redb.Identity.Core.Routes.Processors.ManagementBearerAuthProcessor(
                    validationFactory, validationDispatcher, opts.ScimScope);
                bridgeLogger?.LogInformation(
                    "[Identity.Core.InitRoute] Built ScimAuth processor (scope={Scope})", opts.ScimScope);
            }
        }
        catch (Exception ex)
        {
            bridgeLogger?.LogError(ex, "[Identity.Core.InitRoute] Failed to build management/SCIM auth processors");
        }

        var builder = new IdentityCoreRouteBuilder(identitySp, options, null, managementAuth, scimAuth);
        ((RouteContext)context).AddRoutes(builder);

        return context;
    }

    /// <summary>
    /// N7-1 — assembles the set of OAuth scopes acceptable at the management-API gate:
    /// full-admin master (<c>opts.ManagementScope</c>), self-service
    /// (<c>opts.AccountScope</c>) and every granular admin scope registered via
    /// <see cref="redb.Identity.Contracts.Configuration.IdentityScopes.GranularAdmin"/>.
    /// The per-path <c>GranularScopeGuardProcessor</c> downstream is what actually
    /// decides whether a granular-only token may reach a given controller.
    /// </summary>
    private static string[] BuildAcceptableManagementScopes(
        redb.Identity.Core.Configuration.RedbIdentityOptions opts)
    {
        var granular = redb.Identity.Contracts.Configuration.IdentityScopes.GranularAdmin;
        var result = new string[2 + granular.Length];
        result[0] = opts.ManagementScope;
        result[1] = opts.AccountScope;
        Array.Copy(granular, 0, result, 2, granular.Length);
        return result;
    }
}

/// <summary>
/// Disposes the long-lived scope used to keep <see cref="IOpenIddictValidationFactory"/>
/// (a scoped service) alive for the lifetime of the bridged <c>ManagementBearerAuthProcessor</c>.
/// </summary>
internal sealed class BridgeScopeDisposeListener : IRouteLifecycleListener
{
    private readonly IServiceScope _scope;
    public BridgeScopeDisposeListener(IServiceScope scope) => _scope = scope;
    public Task OnContextStopped(IRouteContext context, CancellationToken ct)
    {
        try { _scope.Dispose(); } catch { /* best effort */ }
        return Task.CompletedTask;
    }
}