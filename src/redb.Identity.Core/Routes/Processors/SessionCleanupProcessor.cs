using Microsoft.Extensions.Options;
using redb.Core;
using redb.Core.Services;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.RedbCore.Extensions;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// Periodic cleanup of revoked sessions older than retention period.
/// Mirrors <see cref="TokenCleanupProcessor"/> pattern: when an
/// <see cref="IBackgroundDeletionService"/> is registered, uses cluster-safe
/// claim-pattern soft delete; otherwise falls back to direct hard delete.
/// </summary>
internal sealed class SessionCleanupProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;
    private readonly RedbIdentityOptions _options;
    private readonly IBackgroundDeletionService? _backgroundDeletion;
    private readonly TimeProvider _timeProvider;

    public SessionCleanupProcessor(
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
        var threshold = now.AddDays(-_options.SessionRetentionDays);
        const int batchSize = 500;

        // S-track: PASS 1 — expire active sessions that crossed either timeout.
        // Mark them as "revoked" so they fall through to the deletion pass on
        // the next run after SessionRetentionDays. We load + filter + save
        // server-side; the IsExpired predicate uses the same idle/absolute
        // timeouts SessionService.ListAsync applies lazily.
        var activeSessions = await redb.Query<SessionProps>()
            .Where(s => s.Status == "active")
            .Take(batchSize)
            .ToListAsync();

        var idleCutoff = now - _options.SessionIdleTimeout;
        var absoluteCutoff = now - _options.SessionAbsoluteTimeout;
        var expiredActive = 0;
        var freshlyRevokedIds = new HashSet<long>();
        foreach (var s in activeSessions)
        {
            var createdAt = s.date_create;
            var isAbsoluteExpired = createdAt is { } c && c < absoluteCutoff;
            var isIdleExpired = s.Props.LastAccessedAt is { } la
                ? la < idleCutoff
                : createdAt is { } c2 && c2 < idleCutoff;
            if (isAbsoluteExpired || isIdleExpired)
            {
                s.Props.Status = "revoked";
                await redb.SaveAsync(s);
                expiredActive++;
                freshlyRevokedIds.Add(s.Id);
            }
        }

        // Revoked sessions older than retention → soft delete via background service if available.
        // Per design (PASS 1's commentary): sessions freshly revoked in this run
        // are NOT pruned in the same call — they fall through to the deletion
        // pass on the next run after SessionRetentionDays. Exclude them by id.
        var revokedIds = (await redb.Query<SessionProps>()
            .WhereRedb(o => o.DateCreate < threshold)
            .Where(s => s.Status == "revoked")
            .Take(batchSize)
            .Select(o => o.Id)
            .ToListAsync())
            .Where(id => !freshlyRevokedIds.Contains(id))
            .ToList();

        if (revokedIds.Count > 0)
        {
            await SoftDeleteAsync(redb, revokedIds, batchSize);
        }

        exchange.Out ??= new Message();
        exchange.Out.Body = new { prunedSessions = revokedIds.Count, expiredActiveSessions = expiredActive };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.SessionsPruned;
        exchange.Properties["identity-event-data"] = new
        {
            SessionCount = revokedIds.Count,
            ExpiredActive = expiredActive,
            Threshold = threshold
        };
    }

    private Task SoftDeleteAsync(IRedbService redb, List<long> ids, int batchSize)
        => IdentityDeletionHelper.DeleteAsync(redb, _backgroundDeletion, ids, batchSize);
}
