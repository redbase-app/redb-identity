using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Identity.DataProtection;
using redb.Route.Abstractions;
using redb.Identity.Core.Routes;

namespace redb.Identity.Core.DataProtection;

/// <summary>
/// Reloads the DataProtection XML key-ring snapshot from PROPS storage into
/// <see cref="RedbXmlRepository"/>. Fired per-tick by a <c>timer://</c> route
/// (see <see cref="Routes.IdentityCoreRouteBuilder"/>). Runs on <b>every</b> replica —
/// this is intentionally NOT cluster-leader-only because each node maintains its own
/// in-process snapshot and must pick up keys rotated by other replicas.
/// </summary>
internal sealed class XmlRepositoryRefreshProcessor : IProcessor
{
    private readonly IServiceProvider _sp;

    public XmlRepositoryRefreshProcessor(IServiceProvider sp)
    {
        ArgumentNullException.ThrowIfNull(sp);
        _sp = sp;
    }

    public async Task Process(IExchange exchange, CancellationToken ct)
    {
        await using var scope = _sp.CreateAsyncScope();
        var repo = scope.ServiceProvider.GetRequiredService<RedbXmlRepository>();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var logger = scope.ServiceProvider
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger<XmlRepositoryRefreshProcessor>();

        var count = await repo.ReloadAsync(redb, ct).ConfigureAwait(false);

        logger.LogDebug(
            "redb.Identity: DataProtection key-ring snapshot refreshed ({Count} keys)",
            count);
    }
}
