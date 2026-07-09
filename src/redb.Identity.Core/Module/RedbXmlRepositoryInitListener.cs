using System.Collections.Immutable;
using System.Xml.Linq;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Core;
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

        // Bounded read: most recent N keys. DataProtection key-ring rarely exceeds a
        // handful of active keys; cap protects against unbounded growth.
        var keys = await redb.Query<DataProtectionKeyProps>()
            .OrderByDescendingRedb(o => o.DateCreate)
            .Take(100)
            .ToListAsync()
            .ConfigureAwait(false);

        var elements = ImmutableArray.CreateBuilder<XElement>(keys.Count);
        foreach (var key in keys)
        {
            if (!string.IsNullOrEmpty(key.Props.XmlContent))
                elements.Add(XElement.Parse(key.Props.XmlContent));
        }
        repo.ReplaceSnapshot(elements.ToImmutable());

        logger.LogInformation(
            "redb.Identity: DataProtection key-ring snapshot loaded ({Count} keys)",
            elements.Count);
    }
}
