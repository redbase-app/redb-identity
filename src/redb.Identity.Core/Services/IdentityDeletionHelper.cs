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
/// Strategy:
/// <list type="bullet">
///   <item><b>Primary:</b> enqueue via <see cref="IBackgroundDeletionService"/>.
///   The service marks objects with the trash scheme (so they immediately disappear
///   from regular Query results) and physically purges them on a background
///   connection in batches.</item>
///   <item><b>Fallback:</b> when no background service is registered (rare; typically
///   misconfigured DI in tests or minimal hosts), call <see cref="IObjectStorageProvider.SoftDeleteAsync(IEnumerable{long}, long?)"/>.
///   This still re-parents objects under the trash scheme so they vanish from
///   Query, but no physical purge is scheduled — operators must run a maintenance
///   job. A warning is logged so the misconfiguration is visible.</item>
/// </list>
/// </para>
/// </summary>
internal static class IdentityDeletionHelper
{
    /// <summary>Bulk delete by ids using the Identity-wide pattern.</summary>
    public static async Task DeleteAsync(
        IRedbService redb,
        IBackgroundDeletionService? backgroundDeletion,
        IEnumerable<long> objectIds,
        int batchSize = 10,
        ILogger? logger = null)
    {
        var ids = objectIds as IList<long> ?? objectIds.ToList();
        if (ids.Count == 0) return;

        if (backgroundDeletion is not null)
        {
            var user = redb.SecurityContext.GetEffectiveUser();
            await backgroundDeletion.DeleteAsync(ids, user, batchSize).ConfigureAwait(false);
            return;
        }

        // Fallback: still hide from queries by re-parenting under the trash scheme.
        // No physical purge — IBackgroundDeletionService should be registered in production.
        logger?.LogWarning(
            "IBackgroundDeletionService is not registered. Falling back to SoftDelete only " +
            "(no physical purge will run). Count={Count}",
            ids.Count);
        await redb.SoftDeleteAsync(ids).ConfigureAwait(false);
    }

    /// <summary>Delete a single object by id using the Identity-wide pattern.</summary>
    public static Task DeleteAsync(
        IRedbService redb,
        IBackgroundDeletionService? backgroundDeletion,
        long objectId,
        int batchSize = 10,
        ILogger? logger = null)
        => DeleteAsync(redb, backgroundDeletion, new[] { objectId }, batchSize, logger);

    /// <summary>Delete by IRedbObject reference using the Identity-wide pattern.</summary>
    public static Task DeleteAsync(
        IRedbService redb,
        IBackgroundDeletionService? backgroundDeletion,
        IRedbObject obj,
        int batchSize = 10,
        ILogger? logger = null)
        => DeleteAsync(redb, backgroundDeletion, new[] { obj.Id }, batchSize, logger);

    /// <summary>Delete by IRedbObject collection using the Identity-wide pattern.</summary>
    public static Task DeleteAsync(
        IRedbService redb,
        IBackgroundDeletionService? backgroundDeletion,
        IEnumerable<IRedbObject> objects,
        int batchSize = 10,
        ILogger? logger = null)
        => DeleteAsync(redb, backgroundDeletion, objects.Select(o => o.Id), batchSize, logger);
}
