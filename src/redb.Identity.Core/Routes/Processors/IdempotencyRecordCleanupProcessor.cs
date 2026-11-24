using Microsoft.Extensions.Options;
using redb.Core;
using redb.Core.Services;
using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Routes;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.RedbCore.Extensions;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// Deletes the idempotency records whose time to live has ended (<c>date_complete</c> in the past). The cache
/// already ignores them; without this cleanup they would stay in the database for good, answers and all. Runs
/// leader-only on the timer registered in <see cref="IdentityCoreRouteBuilder"/>, batch after batch of
/// <see cref="RedbIdentityOptions.IdempotencyCleanupBatchSize"/> until no expired record is left. Deletes through
/// <see cref="IdentityDeletionHelper"/>, like the other cleanups. A body <c>{"dryRun":true}</c> counts the expired
/// records and changes nothing.
/// </summary>
internal sealed class IdempotencyRecordCleanupProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;
    private readonly RedbIdentityOptions _options;
    private readonly IBackgroundDeletionService? _backgroundDeletion;
    private readonly TimeProvider _timeProvider;

    public IdempotencyRecordCleanupProcessor(
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
        var batchSize = Math.Max(1, _options.IdempotencyCleanupBatchSize);

        if (exchange.In.Body is Dictionary<string, object?> body
            && body.TryGetValue("dryRun", out var raw)
            && (raw is true || (raw is string s && bool.TryParse(s, out var parsed) && parsed)))
        {
            var expired = await redb.Query<IdempotencyRecordProps>()
                .WhereRedb(o => o.DateComplete < now)
                .CountAsync()
                .ConfigureAwait(false);

            exchange.Out ??= new Message();
            exchange.Out.Body = new { dryRun = true, wouldPruneIdempotencyRecords = expired, threshold = now };
            exchange.Properties["identity-event-type"] = IdentityAuditEventIds.IdempotencyRecordsPrunePreviewed;
            exchange.Properties["identity-event-data"] = new { Count = expired, Threshold = now };
            return;
        }

        var pruned = 0;
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            var ids = await redb.Query<IdempotencyRecordProps>()
                .WhereRedb(o => o.DateComplete < now)
                .Take(batchSize)
                .Select(o => o.Id)
                .ToListAsync()
                .ConfigureAwait(false);
            if (ids.Count == 0) break;

            await IdentityDeletionHelper.DeleteAsync(redb, _backgroundDeletion, ids).ConfigureAwait(false);
            pruned += ids.Count;
            if (ids.Count < batchSize) break;
        }

        exchange.Out ??= new Message();
        exchange.Out.Body = new { prunedIdempotencyRecords = pruned };
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.IdempotencyRecordsPruned;
        exchange.Properties["identity-event-data"] = new { Count = pruned, Threshold = now };
    }
}
