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
/// B3: periodic cleanup of <see cref="MfaOtpProps"/> rows whose <see cref="MfaOtpProps.ExpiresAt"/>
/// is in the past. Mirrors <see cref="SessionCleanupProcessor"/> — uses
/// <see cref="IBackgroundDeletionService"/> claim-pattern soft delete when available,
/// falls back to direct hard delete otherwise.
/// <para>
/// Verify requests with expired rows already fail with <c>Reason = "expired"</c> inside
/// <c>PropsServerSideOtpStore.VerifyAndConsumeAsync</c>, so the cleanup route is purely a
/// storage-size hygiene measure — it does NOT guard against replay (single-use is enforced
/// at verify time under <c>LockForUpdate</c>).
/// </para>
/// </summary>
internal sealed class MfaOtpCleanupProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;
    private readonly IBackgroundDeletionService? _backgroundDeletion;
    private readonly TimeProvider _timeProvider;

    public MfaOtpCleanupProcessor(
        IRouteContext context,
        string? redbName = null,
        IBackgroundDeletionService? backgroundDeletion = null,
        TimeProvider? timeProvider = null)
    {
        _context = context;
        _redbName = redbName;
        _backgroundDeletion = backgroundDeletion;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var redb = _context.GetRedbService(_redbName, exchange);
        var now = _timeProvider.GetUtcNow();
        const int batchSize = 500;

        var expiredIds = await redb.Query<MfaOtpProps>()
            .Where(o => o.ExpiresAt < now)
            .Take(batchSize)
            .Select(o => o.Id)
            .ToListAsync();

        if (expiredIds.Count > 0)
        {
            await SoftDeleteAsync(redb, expiredIds, batchSize);
        }

        exchange.Out ??= new Message();
        exchange.Out.Body = new { prunedMfaOtp = expiredIds.Count };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.MfaOtpPruned;
        exchange.Properties["identity-event-data"] = new
        {
            RowCount = expiredIds.Count,
            Threshold = now
        };
    }

    private Task SoftDeleteAsync(IRedbService redb, List<long> ids, int batchSize)
        => IdentityDeletionHelper.DeleteAsync(redb, _backgroundDeletion, ids, batchSize);
}
