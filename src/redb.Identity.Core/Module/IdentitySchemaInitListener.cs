using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Attributes;
using redb.Core.Providers;
using redb.Identity.Core.Hosting;
using redb.Route.Abstractions;

namespace redb.Identity.Core.Module;

/// <summary>
/// Initializes redb base infrastructure (_objects/_schemes/_values/etc.) and synchronises all
/// Identity PROPS schemas (<see cref="IdentitySchemaRegistry.Types"/>) before any Identity route
/// starts. Registered from <see cref="InitRoute.main"/> via
/// <c>context.AddLifecycleListener(...)</c>. Runs in <see cref="OnContextStarting"/> —
/// guaranteed to complete BEFORE any route (including the HTTP facade) processes its first
/// exchange, so downstream processors can assume every <c>*Props</c> scheme exists.
/// <para>
/// <b>A6 cluster coordination (opt-in):</b> when <c>IDistributedLock</c> is registered in the
/// root service provider (i.e. when <c>Tsak:Cluster:Enabled=true</c> and the Pro cluster
/// primitives are available), acquires an exclusive short-TTL lock
/// (<c>identity:schema-init</c>) before running DDL so that concurrent cold-starts on
/// multiple replicas do not race each other on <c>CREATE TABLE IF NOT EXISTS</c>. In
/// standalone (the DI service is absent) the coordination block is a no-op.
/// </para>
/// </summary>
internal sealed class IdentitySchemaInitListener : IRouteLifecycleListener
{
    private readonly IServiceProvider _sp;

    public IdentitySchemaInitListener(IServiceProvider sp) => _sp = sp;

    public async Task OnContextStarting(IRouteContext context, CancellationToken ct)
    {
        await using var scope = _sp.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var logger = scope.ServiceProvider
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger<IdentitySchemaInitListener>();

        // A6 cluster lock — only when Tsak cluster primitives are registered.
        // Duck-typed via reflection to avoid a hard reference to redb.Tsak.Core.Pro from
        // redb.Identity.Core. Presence of the lock service indicates Tsak:Cluster:Enabled=true.
        var lockService = TryResolveDistributedLock(_sp);
        var nodeId = Environment.MachineName;
        object? acquired = null;
        if (lockService is not null)
        {
            acquired = await TryAcquireDistributedLockAsync(lockService, "identity:schema-init", nodeId, ttlSeconds: 120, ct)
                .ConfigureAwait(false);
            if (acquired is null)
            {
                logger.LogInformation("redb.Identity: schema init — follower; another node holds the lock, proceeding idempotently");
            }
            else
            {
                logger.LogInformation("redb.Identity: schema init — leader under cluster lock");
            }
        }

        try
        {
            logger.LogInformation("redb.Identity: initializing redb base schema");
            await redb.InitializeAsync(ensureCreated: true).ConfigureAwait(false);

            // Eagerly synchronise every registered Identity Props type so downstream code
            // (processors, listeners) never triggers a lazy DDL from inside a hot path.
            var syncMethod = typeof(ISchemeSyncProvider)
                .GetMethod(nameof(ISchemeSyncProvider.SyncSchemeAsync))
                ?? throw new InvalidOperationException("ISchemeSyncProvider.SyncSchemeAsync not found.");
            foreach (var t in IdentitySchemaRegistry.Types)
            {
                var generic = syncMethod.MakeGenericMethod(t);
                var task = (Task?)generic.Invoke(redb, null);
                if (task is not null) await task.ConfigureAwait(false);

                // CRITICAL: explicitly register each (scheme_id ↔ CLR Type)
                // pair in GlobalMetadataCache. Without this every polymorphic
                // load path — TreeQueryProviderBase.LoadObjectsByIdsAsync
                // (non-generic, which the tree ancestor walk uses to load
                // parent objects whose scheme is only known at runtime) —
                // throws "Type not found for scheme_id=N" and the catch
                // upstack silently degrades the `groups` claim to
                // direct-membership-only.
                //
                // The library's auto-scan (InitializeTypeRegistryAsync) walks
                // AppDomain assemblies looking for [RedbScheme] types, but
                // Tsak loads Identity's types into a child ALC + the scan
                // catches ReflectionTypeLoadException silently — so the
                // registry comes up empty in production. Explicit registration
                // by the schema initializer eliminates that race entirely.
                var attr = t.GetCustomAttribute<RedbSchemeAttribute>();
                if (attr is not null)
                {
                    var schemeName = attr.GetSchemeName(t);
                    var scheme = await redb.GetSchemeByNameAsync(schemeName).ConfigureAwait(false);
                    if (scheme is not null)
                    {
                        redb.Cache.RegisterClrType(schemeName, scheme.Id, t);
                    }
                }
            }

            logger.LogInformation(
                "redb.Identity: redb base schema ready ({Count} scheme types synced + CLR type registry populated)",
                IdentitySchemaRegistry.Types.Count);
        }
        finally
        {
            if (lockService is not null && acquired is not null)
            {
                await ReleaseDistributedLockAsync(lockService, "identity:schema-init", nodeId, ct)
                    .ConfigureAwait(false);
            }
        }
    }

    private static object? TryResolveDistributedLock(IServiceProvider sp)
    {
        // Resolve redb.Tsak.Core.Pro.Cluster.Contracts.IDistributedLock without a compile-time
        // reference — Identity.Core must build regardless of Pro presence.
        var type = Type.GetType("redb.Tsak.Core.Pro.Cluster.Contracts.IDistributedLock, redb.Tsak.Core.Pro", throwOnError: false);
        return type is null ? null : sp.GetService(type);
    }

    private static async Task<object?> TryAcquireDistributedLockAsync(object lockService, string name, string nodeId, int ttlSeconds, CancellationToken ct)
    {
        var method = lockService.GetType().GetMethod("TryAcquireAsync")
            ?? throw new InvalidOperationException("IDistributedLock.TryAcquireAsync not found.");
        var task = (Task?)method.Invoke(lockService, [name, nodeId, "identity", ttlSeconds, ct])
            ?? throw new InvalidOperationException("IDistributedLock.TryAcquireAsync returned null.");
        await task.ConfigureAwait(false);
        var result = task.GetType().GetProperty("Result")?.GetValue(task);
        var acquired = (bool?)(result?.GetType().GetProperty("Acquired")?.GetValue(result)) ?? false;
        return acquired ? result : null;
    }

    private static async Task ReleaseDistributedLockAsync(object lockService, string name, string nodeId, CancellationToken ct)
    {
        var method = lockService.GetType().GetMethod("ReleaseAsync")
            ?? throw new InvalidOperationException("IDistributedLock.ReleaseAsync not found.");
        var task = (Task?)method.Invoke(lockService, [name, nodeId, "identity", ct]);
        if (task is not null) await task.ConfigureAwait(false);
    }
}

