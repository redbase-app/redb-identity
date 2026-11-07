using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Exceptions;
using redb.Core.Models.Entities;
using redb.Core.Query;
using redb.Identity.Core.Models;
using redb.Identity.Core.Routes.Processors;

namespace redb.Identity.Core.Services;

/// <summary>
/// PROPS-backed <see cref="IDpopReplayStore"/> mirroring
/// <see cref="redb.Identity.Core.Mfa.PropsWebAuthnChallengeStore"/>. Singleton; resolves
/// <see cref="IRedbService"/> through a fresh DI scope per operation to avoid
/// captive-scope-in-singleton.
/// <para>
/// Atomicity (RFC 9449 §11.1, at most once): the reservation row carries
/// <c>ValueUnique</c> = SHA-256 of <c>jkt|jti</c>, so the database index decides who wins, not
/// the lookup. Two presentations of one proof racing past <c>FirstOrDefaultAsync</c> both try
/// to insert; the index lets exactly one through and the other gets
/// <see cref="RedbUniqueViolationException"/>, reported as a replay. The lookup stays as the
/// fast path — an already-consumed proof is refused without a failing statement — and an
/// expired reservation is refreshed in place rather than inserted a second time.
/// </para>
/// <para>
/// The key is hashed for the reason the idempotency record's is (owner decision R5(v)):
/// <c>jti</c> is chosen by the client and unbounded, while <c>ValueUnique</c> is capped at 440
/// characters. Rows written before the key existed carry none; the lookup still finds them,
/// and the cleanup timer removes them within one TTL.
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
        var expiresAt = now + (ttl <= TimeSpan.Zero ? TimeSpan.FromMinutes(5) : ttl);
        var name = jkt + "|" + jti;
        var uniqueKey = IdempotencyKeyHash.Sha256Hex(name);

        await using var scope = _scopeFactory.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();

        // ExecuteAtomicAsync rather than an explicit transaction: it joins the ambient one when
        // the route is transacted (the token route is) and opens its own when it is not. An
        // explicit BeginTransactionAsync can do neither — the core rejects it under an ambient
        // scope — and a mid-logic rollback would discard the whole route: a replayed proof must
        // fail the request, not undo everything before it.
        return await redb.Context.ExecuteAtomicAsync(async () =>
        {
            var existing = await redb.Query<DpopConsumedJtiProps>()
                .Where(o => o.Jkt == jkt && o.Jti == jti)
                .FirstOrDefaultAsync()
                .ConfigureAwait(false);

            if (existing is not null)
            {
                // A live reservation is a replay.
                if (existing.Props.ExpiresAt > now)
                {
                    _logger.LogWarning("DPoP proof replay detected: jkt={Jkt} jti={Jti}", jkt, jti);
                    return false;
                }

                // Expired — cleanup has not run yet. Refresh the row in place: a second insert
                // would hit the unique key and misreport a stale row as a replay. A proof this
                // old is refused by the iat window long before it reaches the store, so this
                // branch is housekeeping, not the guard.
                existing.Props.ConsumedAt = now;
                existing.Props.ExpiresAt = expiresAt;
                existing.ValueUnique = uniqueKey;
                await redb.SaveAsync(existing).ConfigureAwait(false);
                return true;
            }

            var row = new RedbObject<DpopConsumedJtiProps>(new DpopConsumedJtiProps
            {
                Jkt = jkt,
                Jti = jti,
                ConsumedAt = now,
                ExpiresAt = expiresAt,
            });
            row.name = name;
            row.ValueUnique = uniqueKey;

            try
            {
                await redb.SaveAsync(row).ConfigureAwait(false);
                return true;
            }
            catch (RedbUniqueViolationException)
            {
                // The other presenter of this jti inserted between our lookup and our insert.
                // The core ran the insert under a savepoint, so the surrounding transaction (the
                // token route's, when ambient) is intact and the request is refused cleanly.
                _logger.LogWarning("DPoP proof replay detected (concurrent): jkt={Jkt} jti={Jti}", jkt, jti);
                return false;
            }
        }, ct).ConfigureAwait(false);
    }
}
