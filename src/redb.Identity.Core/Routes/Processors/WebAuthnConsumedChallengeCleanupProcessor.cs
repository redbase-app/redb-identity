using redb.Core;
using redb.Core.Services;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.RedbCore.Extensions;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// MFA-3: periodic cleanup of <see cref="WebAuthnConsumedChallengeProps"/> rows whose
/// <see cref="WebAuthnConsumedChallengeProps.ExpiresAt"/> is in the past.
/// <para>
/// Mirrors <see cref="MfaOtpCleanupProcessor"/> exactly \u2014 hash-marker rows are pure
/// storage hygiene, so deleting expired ones is purely a size concern: replay protection is
/// already enforced by the unique index at consume time. Uses <see cref="IBackgroundDeletionService"/>
/// claim-pattern soft delete when available, falls back to direct delete otherwise.
/// </para>
/// </summary>
internal sealed class WebAuthnConsumedChallengeCleanupProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;
    private readonly IBackgroundDeletionService? _backgroundDeletion;
    private readonly TimeProvider _timeProvider;

    public WebAuthnConsumedChallengeCleanupProcessor(
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

        var expiredIds = await redb.Query<WebAuthnConsumedChallengeProps>()
            .Where(o => o.ExpiresAt < now)
            .Take(batchSize)
            .Select(o => o.Id)
            .ToListAsync();

        if (expiredIds.Count > 0)
        {
            await IdentityDeletionHelper.DeleteAsync(redb, _backgroundDeletion, expiredIds, batchSize);
        }

        exchange.Out ??= new Message();
        exchange.Out.Body = new { prunedWebAuthnChallenges = expiredIds.Count };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.MfaOtpPruned;
        exchange.Properties["identity-event-data"] = new
        {
            RowCount = expiredIds.Count,
            Threshold = now,
            Source = "webauthn_consumed_challenge"
        };
    }
}
