using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Models.Contracts;
using redb.Core.Services;

namespace redb.Identity.Core.Services;

/// <summary>
/// Identity-wide deletion pattern.
/// <para>
/// Identity NEVER hard-deletes via <c>redb.DeleteAsync</c> directly. Hard-deletes
/// cascade through the <c>_values</c> PROPS table (an unbounded fan-out for objects
/// with many properties / descendants — User, Application, Authorization, etc.),
/// running synchronously inside the request and able to time out the foreground
/// connection.
/// </para>
/// <para>
/// Strategy: mark here, purge there.
/// <list type="bullet">
///   <item><b>Mark</b> — <see cref="IObjectStorageProvider.SoftDeleteAsync(IEnumerable{long}, IRedbUser, long?, CancellationToken)"/>
///   on the <b>caller's</b> <see cref="IRedbService"/>: the objects move under a trash
///   container and vanish from regular Query results immediately.</item>
///   <item><b>Purge</b> — <see cref="IBackgroundDeletionService"/> polls for trash
///   containers and physically deletes them on its own connection. It finds the
///   container written above by itself; nothing has to be handed to it.</item>
/// </list>
/// </para>
/// <para>
/// The mark deliberately does NOT go through <see cref="IBackgroundDeletionService.DeleteAsync"/>.
/// That method opens its own DI scope, i.e. a <b>second connection</b>, and marks there.
/// Under a route-level transaction (<c>WithRedbTx</c>, active whenever
/// <c>RedbInstanceName</c> is configured) that second connection fights the first:
/// on SQLite it waits on the writer lock held by the route transaction and fails after
/// the busy timeout (~34 s), and on PostgreSQL / MSSQL the mark either blocks on the
/// row locks of an object the route already wrote, or commits on its own — so a route
/// that fails afterwards rolls back everything except the deletion. Marking on the
/// caller's service joins whatever transaction that service is in (<c>SoftDeleteAsync</c>
/// runs through <c>ExecuteAtomicAsync</c>), so the deletion commits and rolls back with
/// the rest of the operation.
/// </para>
/// </summary>
internal static class IdentityDeletionHelper
{
    /// <summary>Bulk delete by ids using the Identity-wide pattern.</summary>
    public static async Task DeleteAsync(
        IRedbService redb,
        IBackgroundDeletionService? backgroundDeletion,
        IEnumerable<long> objectIds,
        ILogger? logger = null)
    {
        var ids = objectIds as IList<long> ?? objectIds.ToList();
        if (ids.Count == 0) return;

        if (backgroundDeletion is null)
        {
            // The mark below still hides the objects from every query, but nothing will
            // physically purge them — operators must run a maintenance job. Worth a warning:
            // in production the service is registered by the provider's DI extension.
            logger?.LogWarning(
                "IBackgroundDeletionService is not registered. Objects will be marked deleted " +
                "but no physical purge will run. Count={Count}",
                ids.Count);
        }

        // Always on the caller's service — see the class remarks for why the background
        // service's own DeleteAsync (a second connection) must not do this.
        await redb.SoftDeleteAsync(ids, redb.SecurityContext.GetEffectiveUser()).ConfigureAwait(false);
    }

    /// <summary>Delete a single object by id using the Identity-wide pattern.</summary>
    public static Task DeleteAsync(
        IRedbService redb,
        IBackgroundDeletionService? backgroundDeletion,
        long objectId,
        ILogger? logger = null)
        => DeleteAsync(redb, backgroundDeletion, new[] { objectId }, logger);

    /// <summary>Delete by IRedbObject reference using the Identity-wide pattern.</summary>
    public static Task DeleteAsync(
        IRedbService redb,
        IBackgroundDeletionService? backgroundDeletion,
        IRedbObject obj,
        ILogger? logger = null)
        => DeleteAsync(redb, backgroundDeletion, new[] { obj.Id }, logger);

    /// <summary>Delete by IRedbObject collection using the Identity-wide pattern.</summary>
    public static Task DeleteAsync(
        IRedbService redb,
        IBackgroundDeletionService? backgroundDeletion,
        IEnumerable<IRedbObject> objects,
        ILogger? logger = null)
        => DeleteAsync(redb, backgroundDeletion, objects.Select(o => o.Id), logger);
}
