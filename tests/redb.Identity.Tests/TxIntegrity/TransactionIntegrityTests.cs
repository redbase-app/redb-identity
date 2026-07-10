using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using redb.Identity.Core.Routes;

namespace redb.Identity.Tests.TxIntegrity;

/// <summary>
/// G6 — transaction integrity on real PostgreSQL.
/// <para>
/// Covers the minimum invariants every tx-wrapping route relies on
/// (<see cref="redb.Identity.Core.Routes.IdentityCoreRouteBuilder"/> WithRedbTx /
/// WithIdempotentTx helpers, <c>MfaVerifyProcessor</c>, <c>MfaRecoveryProcessor</c>,
/// <c>PropsServerSideOtpStore.VerifyAndConsumeAsync</c>):
/// <list type="number">
///   <item>explicit commit persists;</item>
///   <item>explicit rollback discards;</item>
///   <item>dispose without commit ≡ rollback (the C# <c>await using</c> pattern
///   every processor uses MUST not silently leak partial writes on exception paths);</item>
///   <item>mutations made inside a transaction are NOT visible to a concurrent
///   reader until commit (isolation — prevents TOCTOU in the MFA verify / consume
///   lock pattern).</item>
/// </list>
/// Without these guarantees, a mid-flow exception (network blip, timeout,
/// <c>OperationCanceledException</c>) in an MFA verify would leave partially
/// consumed rows and a recovery-code double-spend regression would resurface.
/// </para>
/// </summary>
[Collection("Postgres")]
public sealed class TransactionIntegrityTests
{
    private readonly PostgresFixture _fx;

    public TransactionIntegrityTests(PostgresFixture fx) => _fx = fx;

    // Use SessionProps — already schema-synced in PostgresFixture, plain model, cheap to create.
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

    [Fact]
    public async Task CommitAsync_PersistsWrites()
    {
        var userId = NewUserId();
        await using var tx = await _fx.Redb.Context.BeginTransactionAsync();

        var obj = new RedbObject<SessionProps> { key = userId, Props = MakeSession() };
        var id = await _fx.Redb.SaveAsync(obj);
        id.Should().BeGreaterThan(0);

        await tx.CommitAsync();

        var count = await CountSessionsForAsync(userId);
        count.Should().Be(1,
            "after an explicit CommitAsync the SessionProps row must be visible " +
            "to subsequent queries — otherwise WithRedbTx-wrapped processors " +
            "(logout, consent, MFA setup) would silently drop their state.");
    }

    [Fact]
    public async Task RollbackAsync_DiscardsWrites()
    {
        var userId = NewUserId();

        await using (var tx = await _fx.Redb.Context.BeginTransactionAsync())
        {
            var obj = new RedbObject<SessionProps> { key = userId, Props = MakeSession() };
            await _fx.Redb.SaveAsync(obj);

            await tx.RollbackAsync();
        }

        var count = await CountSessionsForAsync(userId);
        count.Should().Be(0,
            "an explicit RollbackAsync must discard all writes made inside the tx. " +
            "A mid-route failure path that issues RollbackAsync (see the catch blocks " +
            "around BeginTransactionAsync in MfaVerifyProcessor) must leave the DB " +
            "in its pre-tx state.");
    }

    [Fact]
    public async Task DisposeWithoutCommit_BehavesAsRollback()
    {
        var userId = NewUserId();

        // Scope the `await using` so we can assert AFTER disposal.
        {
            await using var tx = await _fx.Redb.Context.BeginTransactionAsync();
            var obj = new RedbObject<SessionProps> { key = userId, Props = MakeSession() };
            await _fx.Redb.SaveAsync(obj);
            // intentionally no CommitAsync — simulates an exception escaping the block
        }

        var count = await CountSessionsForAsync(userId);
        count.Should().Be(0,
            "the `await using (var tx = … BeginTransactionAsync())` pattern used by " +
            "every Identity tx-wrapped processor relies on Dispose ≡ Rollback when " +
            "no explicit commit ran. If a throw escapes the try block, the row must " +
            "not persist — otherwise a mid-flight exception in MFA / consent / logout " +
            "would leak half-written state.");
    }

    [Fact]
    public async Task UncommittedWrites_AreInvisibleToConcurrentReaders()
    {
        // Isolation guard (PostgreSQL READ COMMITTED default): writes inside an open tx
        // must NOT be visible to a fresh connection until commit. This is the foundation
        // of the MFA verify / OTP consume lock pattern in PropsServerSideOtpStore.
        var userId = NewUserId();

        await using var tx = await _fx.Redb.Context.BeginTransactionAsync();
        var obj = new RedbObject<SessionProps> { key = userId, Props = MakeSession() };
        await _fx.Redb.SaveAsync(obj);

        // The outside observer uses its own connection / session by querying via a
        // fresh IRedbService resolution. In the test ServiceProvider `IRedbService` is
        // scoped per-request and its `Context` owns the connection; resolving a new
        // one from a fresh scope gives us an independent connection.
        await using var readerScope = _fx.Services.CreateAsyncScope();
        var readerRedb = readerScope.ServiceProvider.GetRequiredService<IRedbService>();

        var countBeforeCommit = (await readerRedb.Query<SessionProps>()
            .WhereRedb(o => o.Key == userId)
            .ToListAsync()).Count;

        countBeforeCommit.Should().Be(0,
            "uncommitted writes must be invisible to an independent connection " +
            "(default READ COMMITTED isolation). Otherwise two concurrent MFA verifies " +
            "could both observe 'Consumed=false' under a FOR UPDATE lock that isn't " +
            "actually serializing them — recovery-code double-spend would resurface.");

        await tx.CommitAsync();

        var countAfterCommit = (await readerRedb.Query<SessionProps>()
            .WhereRedb(o => o.Key == userId)
            .ToListAsync()).Count;
        countAfterCommit.Should().Be(1,
            "after commit, the independent reader must see the row.");
    }

    private static long NewUserId() =>
        DateTimeOffset.UtcNow.UtcTicks + Random.Shared.Next(1_000_000, 10_000_000);
}
