using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Core.Services;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.TxIntegrity;

/// <summary>
/// Identity deletions must take part in the caller's transaction.
///
/// <para>
/// Every Identity deletion goes through <see cref="IdentityDeletionHelper"/>. It used to
/// hand the mark to <c>IBackgroundDeletionService.DeleteAsync</c>, which opens its own DI
/// scope — a <b>second connection</b> — and marks there. Under a route-level transaction
/// (<c>WithRedbTx</c>, live whenever <c>RedbInstanceName</c> is configured, i.e. in every
/// Tsak-hosted deployment) that second connection fights the first: on SQLite it waits on
/// the writer lock the route transaction holds and dies on the busy timeout (~34 s), and on
/// PostgreSQL / MSSQL the mark commits on its own — so a route failing after the deletion
/// rolled back everything <b>except</b> the deletion.
/// </para>
///
/// <para>
/// These tests pin the invariant directly, without the route stack: an explicit transaction
/// on the same <see cref="IRedbService"/> is the same ambient transaction <c>WithRedbTx</c>
/// opens. Before the fix the rollback test failed on PostgreSQL / MSSQL (the row stayed in
/// the trash) and hung, then failed, on SQLite (writer-lock timeout) — the two faces of the
/// same defect. Handed over from the core side as V5 of the trash-lock incident.
/// </para>
/// </summary>
[Collection("Postgres")]
public sealed class DeletionHelperTransactionTests
{
    private readonly PostgresFixture _fx;

    public DeletionHelperTransactionTests(PostgresFixture fx) => _fx = fx;

    private static long NewUserId() => Random.Shared.NextInt64(1_000_000_000, long.MaxValue);

    // SessionProps: already schema-synced by the fixture, plain model, cheap to create.
    private static SessionProps MakeSession() => new()
    {
        ApplicationObjectId = 0,
        Status = "active",
        MfaVerified = false,
        MfaMethod = null,
    };

    private async Task<long> CountSessionsForAsync(long userId)
        => (await _fx.Redb.Query<SessionProps>()
                .WhereRedb(o => o.Key == userId)
                .ToListAsync()).Count;

    /// <summary>The real service, exactly as the provider's DI extension registers it.</summary>
    private IBackgroundDeletionService BackgroundDeletion
        => _fx.Services.GetRequiredService<IBackgroundDeletionService>();

    [Fact]
    public async Task Mark_RollsBackWithTheCallerTransaction()
    {
        var userId = NewUserId();
        var id = await _fx.Redb.SaveAsync(
            new RedbObject<SessionProps> { key = userId, Props = MakeSession() });
        (await CountSessionsForAsync(userId)).Should().Be(1, "the seed row is committed before the tx opens");

        await using (var tx = await _fx.Redb.Context.BeginTransactionAsync())
        {
            await IdentityDeletionHelper.DeleteAsync(_fx.Redb, BackgroundDeletion, id);

            (await CountSessionsForAsync(userId)).Should().Be(0,
                "inside the transaction the object is already under the trash container");

            await tx.RollbackAsync();
        }

        (await CountSessionsForAsync(userId)).Should().Be(1,
            "the deletion must roll back with the transaction that contained it. A mark written "
            + "on a second connection commits independently, so a route failing after the delete "
            + "would leave the object trashed — deletion without atomicity.");
    }

    [Fact]
    public async Task Mark_CommitsWithTheCallerTransaction()
    {
        var userId = NewUserId();
        var id = await _fx.Redb.SaveAsync(
            new RedbObject<SessionProps> { key = userId, Props = MakeSession() });

        await using (var tx = await _fx.Redb.Context.BeginTransactionAsync())
        {
            await IdentityDeletionHelper.DeleteAsync(_fx.Redb, BackgroundDeletion, id);
            await tx.CommitAsync();
        }

        (await CountSessionsForAsync(userId)).Should().Be(0,
            "a committed deletion stays deleted — the background service finds the trash "
            + "container by polling and purges it later");
    }

    [Fact]
    public async Task Mark_WithoutAmbientTransaction_StillDeletes()
    {
        var userId = NewUserId();
        var id = await _fx.Redb.SaveAsync(
            new RedbObject<SessionProps> { key = userId, Props = MakeSession() });

        await IdentityDeletionHelper.DeleteAsync(_fx.Redb, BackgroundDeletion, id);

        (await CountSessionsForAsync(userId)).Should().Be(0,
            "autocommit callers (cleanup timers, stores outside a route tx) must keep working");
    }
}
