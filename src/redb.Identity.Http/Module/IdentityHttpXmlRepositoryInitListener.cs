using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Identity.DataProtection;
using redb.Route.Abstractions;

namespace redb.Identity.Http.Module;

/// <summary>
/// HTTP-side mirror of <c>RedbXmlRepositoryInitListener</c> from Core: seeds the
/// <see cref="RedbXmlRepository"/> snapshot from PROPS before the first cookie
/// <c>Protect/Unprotect</c> hits the auth hot path.
/// <para>
/// Identity.Core and Identity.Http run in <b>separate</b> Tsak contexts (Phase 8).
/// They share the cluster-wide DataProtection key-ring through redb PROPS (Phase 9a),
/// but each context owns its own <c>RedbXmlRepository</c> singleton inside its child
/// <see cref="IServiceProvider"/>. Without a context-local init listener, the Http
/// repository starts empty and the very first session-cookie request triggers
/// <c>KeyManager</c> to mint a fresh key — invalidating every previously issued
/// session-ticket and breaking SSO continuity across redeploys.
/// </para>
/// </summary>
internal sealed class IdentityHttpXmlRepositoryInitListener : IRouteLifecycleListener
{
    private readonly IServiceProvider _sp;

    public IdentityHttpXmlRepositoryInitListener(IServiceProvider sp) => _sp = sp;

    public async Task OnContextStarting(IRouteContext context, CancellationToken ct)
    {
        await using var scope = _sp.CreateAsyncScope();
        var repo = scope.ServiceProvider.GetRequiredService<RedbXmlRepository>();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var logger = scope.ServiceProvider
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger<IdentityHttpXmlRepositoryInitListener>();

        // The file key ring the process wrote up to 4.3 goes into redb first (idempotent with the
        // Core context, which runs the same import), then the snapshot is loaded.
        await RedbXmlRepository.ImportFileKeyRingsAsync(redb, DefaultFileKeyRing.Directories(), logger, ct)
            .ConfigureAwait(false);
        var count = await repo.ReloadAsync(redb, ct).ConfigureAwait(false);

        logger.LogInformation(
            "redb.Identity.Http: DataProtection key-ring snapshot loaded ({Count} keys)",
            count);
    }
}
