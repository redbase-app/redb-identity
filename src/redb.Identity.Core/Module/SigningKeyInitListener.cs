using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Keys;
using redb.Route.Abstractions;

namespace redb.Identity.Core.Module;

/// <summary>
/// A3: seeds the PROPS signing / encryption key store (<see cref="PropsSigningKeyStore"/>)
/// before the HTTP facade serves the first token request. Required so that the first
/// <c>/connect/token</c> call does not force OpenIddict to fall back to an ephemeral in-memory
/// key (which would split the JWKS across cluster replicas and invalidate tokens on restart).
/// <para>
/// Must run AFTER <c>RedbXmlRepositoryInitListener</c> because the PROPS store encrypts private
/// PEM material with the DataProtection key ring that <c>RedbXmlRepository</c> loads — if the
/// ring is empty, DataProtection will lazily generate its first key here, which is fine.
/// </para>
/// <para>
/// <b>Cluster coordination (A3 + A6 gap — G12 "distributed-lock on kid"):</b> when
/// <c>IDistributedLock</c> is registered in the root service provider (i.e. when
/// <c>Tsak:Cluster:Enabled=true</c> and Pro cluster primitives are available), acquires an
/// exclusive short-TTL lock (<c>identity:keys-init</c>) before invoking
/// <see cref="ISigningKeyStore.EnsureBootstrappedAsync"/> so that a cold-start of N replicas
/// against an empty key store does not result in N concurrent check-then-write paths each
/// generating its own kid → N active keys per kind → JWKS key-set bloat + 90-day rotation
/// cliff when all N expire together. Mirrors <see cref="IdentitySchemaInitListener"/> (A6).
/// In standalone (the DI service is absent) the coordination block is a no-op — within a
/// single process only one lifecycle callback runs, so no in-process race is possible.
/// </para>
/// </summary>
internal sealed class SigningKeyInitListener : IRouteLifecycleListener
{
    private readonly IServiceProvider _sp;

    public SigningKeyInitListener(IServiceProvider sp) => _sp = sp;

    public async Task OnContextStarting(IRouteContext context, CancellationToken ct)
    {
        await using var scope = _sp.CreateAsyncScope();
        var options = scope.ServiceProvider
            .GetRequiredService<Microsoft.Extensions.Options.IOptions<RedbIdentityOptions>>()
            .Value;
        if (!options.UsePropsSigningKeyStore)
            return;

        var store = scope.ServiceProvider.GetRequiredService<ISigningKeyStore>();
        var logger = scope.ServiceProvider
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger<SigningKeyInitListener>();

        // Cluster lock — duck-typed via reflection so redb.Identity.Core stays clean of a
        // compile-time reference to redb.Tsak.Core.Pro. Presence of the service indicates
        // Tsak:Cluster:Enabled=true. See IdentitySchemaInitListener (A6) for the reference
        // pattern; both listeners must use identical acquire/release plumbing because a drift
        // would silently break cluster coordination on one of them.
        var lockService = TryResolveDistributedLock(_sp);
        var nodeId = Environment.MachineName;
        object? acquired = null;
        if (lockService is not null)
        {
            acquired = await TryAcquireDistributedLockAsync(lockService, "identity:keys-init", nodeId, ttlSeconds: 120, ct)
                .ConfigureAwait(false);
            logger.LogInformation(
                acquired is null
                    ? "redb.Identity: signing-key init — follower; another replica is bootstrapping, will no-op via idempotent check"
                    : "redb.Identity: signing-key init — leader under cluster lock identity:keys-init");
        }

        try
        {
            await store.EnsureBootstrappedAsync("signing", ct).ConfigureAwait(false);
            if (!options.DisableAccessTokenEncryption)
                await store.EnsureBootstrappedAsync("encryption", ct).ConfigureAwait(false);

            var materials = await store.GetAllAsync(ct).ConfigureAwait(false);
            logger.LogInformation(
                "redb.Identity: PROPS signing-key store ready ({Count} key(s) loaded)",
                materials.Length);
        }
        finally
        {
            if (lockService is not null && acquired is not null)
            {
                await ReleaseDistributedLockAsync(lockService, "identity:keys-init", nodeId, ct)
                    .ConfigureAwait(false);
            }
        }
    }

    private static object? TryResolveDistributedLock(IServiceProvider sp)
    {
        // Resolve redb.Tsak.Core.Pro.Cluster.Contracts.IDistributedLock without a compile-time
        // reference — Identity.Core must build regardless of Pro presence.
        var type = Type.GetType(
            "redb.Tsak.Core.Pro.Cluster.Contracts.IDistributedLock, redb.Tsak.Core.Pro",
            throwOnError: false);
        return type is null ? null : sp.GetService(type);
    }

    private static async Task<object?> TryAcquireDistributedLockAsync(
        object lockService, string name, string nodeId, int ttlSeconds, CancellationToken ct)
    {
        var method = lockService.GetType().GetMethod("TryAcquireAsync")
            ?? throw new InvalidOperationException("IDistributedLock.TryAcquireAsync not found.");
        var task = (Task?)method.Invoke(lockService, [name, nodeId, "identity", ttlSeconds, ct])
            ?? throw new InvalidOperationException("IDistributedLock.TryAcquireAsync returned null.");
        await task.ConfigureAwait(false);
        var result = task.GetType().GetProperty("Result")?.GetValue(task);
        var isAcquired = (bool?)(result?.GetType().GetProperty("Acquired")?.GetValue(result)) ?? false;
        return isAcquired ? result : null;
    }

    private static async Task ReleaseDistributedLockAsync(
        object lockService, string name, string nodeId, CancellationToken ct)
    {
        var method = lockService.GetType().GetMethod("ReleaseAsync")
            ?? throw new InvalidOperationException("IDistributedLock.ReleaseAsync not found.");
        var task = (Task?)method.Invoke(lockService, [name, nodeId, "identity", ct]);
        if (task is not null) await task.ConfigureAwait(false);
    }
}

