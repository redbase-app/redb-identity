using Microsoft.Extensions.Options;
using redb.Core;
using redb.Core.Services;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.RedbCore.Extensions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// Purges expired/revoked tokens and orphaned authorizations older than the retention period.
/// Uses <see cref="IBackgroundDeletionService"/> for cluster-safe soft-delete + background purge.
/// Invoked manually via "prune" operation on ManageTokens route, or by the timer route.
/// </summary>
internal sealed class TokenCleanupProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;
    private readonly RedbIdentityOptions _options;
    private readonly IBackgroundDeletionService? _backgroundDeletion;
    private readonly TimeProvider _timeProvider;

    public TokenCleanupProcessor(
        IRouteContext context,
        IOptions<RedbIdentityOptions> options,
        string? redbName = null,
        IBackgroundDeletionService? backgroundDeletion = null,
        TimeProvider? timeProvider = null)
    {
        _context = context;
        _redbName = redbName;
        _options = options.Value;
        _backgroundDeletion = backgroundDeletion;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var redb = _context.GetRedbService(_redbName, exchange);
        var now = _timeProvider.GetUtcNow();
        var threshold = now.AddDays(-_options.TokenRetentionDays);
        var batchSize = _options.TokenCleanupBatchSize;

        var dryRun = ExtractDryRun(exchange);

        int prunedTokens = 0;

        // Step 1: Collect non-valid tokens older than retention (IDs only via projection)
        var nonValidIds = await redb.Query<TokenProps>()
            .WhereRedb(o => o.DateCreate < threshold)
            .Where(t => t.Status != Statuses.Valid)
            .Take(batchSize)
            .Select(o => o.Id)
            .ToListAsync();

        // Step 2: Collect expired-but-valid tokens older than retention
        var expiredValidIds = await redb.Query<TokenProps>()
            .WhereRedb(o => o.DateComplete < now)
            .WhereRedb(o => o.DateCreate < threshold)
            .Where(t => t.Status == Statuses.Valid)
            .Take(batchSize)
            .Select(o => o.Id)
            .ToListAsync();

        var allTokenIds = nonValidIds.Concat(expiredValidIds).Distinct().ToList();

        if (dryRun)
        {
            var orphanPreview = await CountOrphanedAuthorizations(redb, threshold);
            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = new
            {
                dryRun = true,
                wouldPruneTokens = allTokenIds.Count,
                wouldPruneAuthorizations = orphanPreview,
                threshold
            };
            exchange.Properties["identity-event-type"] = IdentityAuditEventIds.TokensPrunePreviewed;
            exchange.Properties["identity-event-data"] = new
            {
                TokenCount = allTokenIds.Count,
                AuthorizationCount = orphanPreview,
                Threshold = threshold
            };
            return;
        }

        if (allTokenIds.Count > 0)
        {
            prunedTokens = allTokenIds.Count;
            await SoftDeleteAsync(redb, allTokenIds);
        }

        // Step 3: Prune orphaned authorizations
        var prunedAuths = await PruneOrphanedAuthorizations(redb, threshold);

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new { prunedTokens, prunedAuthorizations = prunedAuths };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.TokensPruned;
        exchange.Properties["identity-event-data"] = new
        {
            TokenCount = prunedTokens,
            AuthorizationCount = prunedAuths,
            Threshold = threshold
        };
    }

    /// <summary>
    /// N7-4 dry-run helper: same selection logic as <see cref="PruneOrphanedAuthorizations"/>
    /// but returns the count of authorizations that would be deleted, without mutating.
    /// </summary>
    private static async Task<int> CountOrphanedAuthorizations(IRedbService redb, DateTimeOffset threshold)
    {
        const int batchSize = 500;
        var candidateIds = await redb.Query<AuthorizationProps>()
            .WhereRedb(o => o.DateCreate < threshold)
            .Where(a => a.Status != Statuses.Valid)
            .Take(batchSize)
            .Select(o => o.Id)
            .ToListAsync();
        if (candidateIds.Count == 0)
            return 0;

        var referencedAuthIds = await redb.Query<TokenProps>()
            .Where(t => candidateIds.Contains(t.AuthorizationObjectId))
            .Select(o => o.Props.AuthorizationObjectId)
            .Distinct()
            .ToListAsync();
        var referenced = referencedAuthIds.ToHashSet();
        return candidateIds.Count(id => !referenced.Contains(id));
    }

    private static bool ExtractDryRun(IExchange exchange)
    {
        if (exchange.In.Body is not Dictionary<string, object?> dict)
            return false;
        if (!dict.TryGetValue("dryRun", out var raw) || raw is null)
            return false;
        return raw switch
        {
            bool b => b,
            string s => bool.TryParse(s, out var parsed) && parsed,
            _ => false
        };
    }

    private Task SoftDeleteAsync(IRedbService redb, List<long> ids)
        => IdentityDeletionHelper.DeleteAsync(redb, _backgroundDeletion, ids, _options.TokenCleanupBatchSize);

    private async Task<int> PruneOrphanedAuthorizations(IRedbService redb, DateTimeOffset threshold)
    {
        const int batchSize = 500;
        var candidateIds = await redb.Query<AuthorizationProps>()
            .WhereRedb(o => o.DateCreate < threshold)
            .Where(a => a.Status != Statuses.Valid)
            .Take(batchSize)
            .Select(o => o.Id)
            .ToListAsync();

        if (candidateIds.Count == 0)
            return 0;

        // Find which authorizations still have associated tokens (IDs only)
        var referencedAuthIds = await redb.Query<TokenProps>()
            .Where(t => candidateIds.Contains(t.AuthorizationObjectId))
            .Select(o => o.Props.AuthorizationObjectId)
            .Distinct()
            .ToListAsync();

        var referencedIds = referencedAuthIds.ToHashSet();

        var toDelete = candidateIds.Where(id => !referencedIds.Contains(id)).ToList();

        if (toDelete.Count == 0)
            return 0;

        await SoftDeleteAsync(redb, toDelete);
        return toDelete.Count;
    }
}
