using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Core.Query;
using redb.Identity.Core.Models;

namespace redb.Identity.Core.Services;

/// <summary>
/// PROPS-backed <see cref="IDpopReplayStore"/> mirroring
/// <see cref="redb.Identity.Core.Mfa.PropsWebAuthnChallengeStore"/>. Singleton; resolves
/// <see cref="IRedbService"/> through a fresh DI scope per operation to avoid
/// captive-scope-in-singleton.
/// <para>
/// Atomicity: lookup-then-insert under transaction. A race between two replays for
/// the same (jkt, jti) pair would have last-writer-wins on the row, but the typical
/// consumer of <see cref="TryReserveAsync"/> is the OpenIddict server pipeline which
/// is single-threaded per request — concurrent replay across cluster nodes is the
/// scenario this backend exists for, and at that scale the database row uniqueness
/// constraint prevents both inserts from succeeding.
/// </para>
/// </summary>
public sealed class RedbDpopReplayStore : IDpopReplayStore
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<RedbDpopReplayStore> _logger;
    private readonly TimeProvider _timeProvider;

    public RedbDpopReplayStore(
        IServiceScopeFactory scopeFactory,
        ILogger<RedbDpopReplayStore> logger,
        TimeProvider? timeProvider = null)
    {
        _scopeFactory = scopeFactory ?? throw new ArgumentNullException(nameof(scopeFactory));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task<bool> TryReserveAsync(string jkt, string jti, TimeSpan ttl, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(jkt) || string.IsNullOrEmpty(jti))
            return false;

        var now = _timeProvider.GetUtcNow();
        var name = jkt + "|" + jti;

        await using var scope = _scopeFactory.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();

        await using var tx = await redb.Context.BeginTransactionAsync().ConfigureAwait(false);

        var existing = await redb.Query<DpopConsumedJtiProps>()
            .Where(o => o.Jkt == jkt && o.Jti == jti)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);

        if (existing is not null)
        {
            await tx.RollbackAsync().ConfigureAwait(false);
            // If the prior reservation has fully expired, allow re-reservation —
            // cleanup may not have run yet. Otherwise treat as replay.
            if (existing.Props.ExpiresAt > now)
            {
                _logger.LogWarning(
                    "DPoP proof replay detected: jkt={Jkt} jti={Jti}", jkt, jti);
                return false;
            }
        }

        var row = new RedbObject<DpopConsumedJtiProps>(new DpopConsumedJtiProps
        {
            Jkt = jkt,
            Jti = jti,
            ConsumedAt = now,
            ExpiresAt = now + (ttl <= TimeSpan.Zero ? TimeSpan.FromMinutes(5) : ttl),
        });
        row.name = name;

        await redb.SaveAsync(row).ConfigureAwait(false);
        await tx.CommitAsync().ConfigureAwait(false);
        return true;
    }
}
