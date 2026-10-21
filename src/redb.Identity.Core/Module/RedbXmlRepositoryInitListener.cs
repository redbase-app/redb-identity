using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using redb.Core;
using redb.Identity.Core.Configuration;
using redb.Identity.DataProtection;
using redb.Route.Abstractions;

namespace redb.Identity.Core.Module;

/// <summary>
/// Loads the DataProtection XML key snapshot into <see cref="RedbXmlRepository"/> before any
/// route (including the HTTP facade) processes its first exchange.
/// <para>
/// Without this listener the very first <c>Protect</c>/<c>Unprotect</c> call would face an
/// empty key ring and force <c>KeyManager</c> to generate a fresh key — invalidating any
/// existing session/refresh-token cookies issued by other replicas. Seeding the snapshot at
/// <see cref="OnContextStarting"/> guarantees consistency across cold starts and restarts.
/// </para>
/// <para>
/// Before loading, file key rings the process wrote up to 4.3 (the ASP.NET Core default directory,
/// plus <see cref="DataProtectionOptions.ImportKeysFromPath"/>) are imported into redb, so data
/// protected with them stays readable (<see cref="RedbXmlRepository.ImportFileKeyRingsAsync"/>).
/// </para>
/// </summary>
internal sealed class RedbXmlRepositoryInitListener : IRouteLifecycleListener
{
    private readonly IServiceProvider _sp;

    public RedbXmlRepositoryInitListener(IServiceProvider sp) => _sp = sp;

    public async Task OnContextStarting(IRouteContext context, CancellationToken ct)
    {
        await using var scope = _sp.CreateAsyncScope();
        var repo = scope.ServiceProvider.GetRequiredService<RedbXmlRepository>();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var logger = scope.ServiceProvider
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger<RedbXmlRepositoryInitListener>();

        var directories = DefaultFileKeyRing.Directories().ToList();
        var explicitPath = scope.ServiceProvider.GetService<IOptions<RedbIdentityOptions>>()?
            .Value.DataProtection.ImportKeysFromPath;
        if (!string.IsNullOrWhiteSpace(explicitPath))
            directories.Add(explicitPath);
        await RedbXmlRepository.ImportFileKeyRingsAsync(redb, directories, logger, ct).ConfigureAwait(false);

        var count = await repo.ReloadAsync(redb, ct).ConfigureAwait(false);

        logger.LogInformation(
            "redb.Identity: DataProtection key-ring snapshot loaded ({Count} keys)",
            count);
    }
}
