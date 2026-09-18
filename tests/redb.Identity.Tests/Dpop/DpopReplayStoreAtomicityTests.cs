using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using redb.Core;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Dpop;

/// <summary>
/// RFC 9449 §11.1: a DPoP proof is consumed at most once, and "at most once" has to hold when
/// the same proof is presented twice at the same instant — that is what a replay is.
/// <para>
/// <see cref="RedbDpopReplayStore"/> used to decide by lookup-then-insert with nothing unique on
/// the row: two presentations racing past the lookup both inserted and both were told "reserved".
/// The reservation now carries a unique key (SHA-256 of <c>jkt|jti</c> in <c>ValueUnique</c>),
/// so the index decides and the loser is refused. These tests pin the three faces of that
/// contract on every provider of the matrix: the race, the plain second presentation, and the
/// expired reservation that must be refreshed in place rather than inserted a second time.
/// </para>
/// </summary>
[Collection("Postgres")]
public sealed class DpopReplayStoreAtomicityTests : IAsyncLifetime
{
    private readonly PostgresFixture _fx;
    private RedbDpopReplayStore _store = null!;

    public DpopReplayStoreAtomicityTests(PostgresFixture fx) => _fx = fx;

    public async Task InitializeAsync()
    {
        // The shared fixture syncs the OpenIddict schemes only; the replay marker is ours to sync.
        await _fx.Redb.SyncSchemeAsync<DpopConsumedJtiProps>();
        _store = new RedbDpopReplayStore(
            _fx.Services.GetRequiredService<IServiceScopeFactory>(),
            NullLogger<RedbDpopReplayStore>.Instance);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private static string NewJkt() => "jkt-" + Guid.NewGuid().ToString("N");
    private static string NewJti() => Guid.NewGuid().ToString("N");

    private async Task<int> RowsForAsync(string jkt, string jti)
        => (await _fx.Redb.Query<DpopConsumedJtiProps>()
                .Where(o => o.Jkt == jkt && o.Jti == jti)
                .ToListAsync()).Count;

    [Fact]
    public async Task ConcurrentPresentations_ExactlyOneIsReserved()
    {
        var jkt = NewJkt();
        var jti = NewJti();
        const int parallelism = 16;

        var results = await Task.WhenAll(Enumerable.Range(0, parallelism)
            .Select(_ => Task.Run(() => _store.TryReserveAsync(jkt, jti, TimeSpan.FromMinutes(5)))));

        results.Count(r => r).Should().Be(1,
            "the same proof presented {0} times at once is a replay {1} times over; only the "
            + "database index can make the lookup-then-insert decide once", parallelism, parallelism - 1);
        (await RowsForAsync(jkt, jti)).Should().Be(1,
            "every extra row is a presentation that was wrongly accepted");
    }

    [Fact]
    public async Task SecondPresentation_IsRefused()
    {
        var jkt = NewJkt();
        var jti = NewJti();
        var ttl = TimeSpan.FromMinutes(5);

        (await _store.TryReserveAsync(jkt, jti, ttl)).Should().BeTrue("first presentation reserves");
        (await _store.TryReserveAsync(jkt, jti, ttl)).Should().BeFalse("the same jti again is a replay");
        (await _store.TryReserveAsync(jkt, NewJti(), ttl)).Should().BeTrue(
            "a different jti under the same key is a different proof");
    }

    [Fact]
    public async Task ExpiredReservation_IsRefreshedInPlace_NotDuplicated()
    {
        var jkt = NewJkt();
        var jti = NewJti();

        (await _store.TryReserveAsync(jkt, jti, TimeSpan.FromMilliseconds(1))).Should().BeTrue();
        await Task.Delay(50);

        (await _store.TryReserveAsync(jkt, jti, TimeSpan.FromMinutes(5))).Should().BeTrue(
            "an expired reservation may be taken again — cleanup simply has not run yet");
        (await RowsForAsync(jkt, jti)).Should().Be(1,
            "the expired row is refreshed, not joined by a second one that the unique key would "
            + "then misreport as a replay");
        (await _store.TryReserveAsync(jkt, jti, TimeSpan.FromMinutes(5))).Should().BeFalse(
            "the refreshed reservation is live again");
    }
}
