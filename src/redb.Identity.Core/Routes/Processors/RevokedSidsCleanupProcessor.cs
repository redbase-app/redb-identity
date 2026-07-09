using Microsoft.Extensions.Options;
using redb.Core;
using redb.Core.Services;
using redb.Identity.Contracts.Routes;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.RedbCore.Extensions;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// W6-0: Periodic cleanup of expired entries in the backchannel revoked-sids list.
/// Runs leader-only (<c>.Cluster(true)</c>) on the timer registered in
/// <see cref="IdentityCoreRouteBuilder"/>. Soft-deletes via <see cref="IdentityDeletionHelper"/>
/// when an <see cref="IBackgroundDeletionService"/> is registered (cluster-safe claim
/// pattern); otherwise falls back to direct hard delete \u2014 mirrors
/// <see cref="SessionCleanupProcessor"/>.
/// </summary>
internal sealed class RevokedSidsCleanupProcessor : IProcessor
{
    private const int BatchSize = 500;

    private readonly IRouteContext _context;
    private readonly string? _redbName;
    private readonly RedbIdentityOptions _options;
    private readonly IBackgroundDeletionService? _backgroundDeletion;
    private readonly TimeProvider _timeProvider;

    public RevokedSidsCleanupProcessor(
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

        // Entries past their ExpiresAt are no longer needed by any RP cache and can be
        // soft-deleted. Note: we don't add a safety margin \u2014 RPs reading the entry on
        // their next poll will already see ExpiresAt in the past and evict it locally.
        var expiredIds = await redb.Query<RevokedSidProps>()
            .WhereRedb(o => o.DateCreate <= now)
            .Where(p => p.ExpiresAt < now)
            .Take(BatchSize)
            .Select(o => o.Id)
            .ToListAsync()
            .ConfigureAwait(false);

        if (expiredIds.Count > 0)
        {
            await IdentityDeletionHelper.DeleteAsync(redb, _backgroundDeletion, expiredIds, BatchSize)
                .ConfigureAwait(false);
        }

        exchange.Out ??= new Message();
        exchange.Out.Body = new { prunedRevokedSids = expiredIds.Count };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.RevokedSidsPruned;
        exchange.Properties["identity-event-data"] = new
        {
            Count = expiredIds.Count,
            Threshold = now
        };
    }
}
