using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Attributes;
using redb.Core.Exceptions;
using redb.Core.Models.Entities;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.V4Unique;

/// <summary>
/// Probe scheme for the V4-UNIQUE refactoring (doc/v4/00-PLAN.md, Ф0). Deliberately its own
/// scheme so no production Identity scheme is touched; keys are Guid-unique per run because
/// the PG/MSSQL test database is shared and never cleaned.
/// </summary>
[RedbScheme("identity.v4probe")]
public class V4UniqueProbeProps
{
    [RedbUnique]
    public string? Code { get; set; }

    public string? Note { get; set; }
}

/// <summary>
/// Ф0 probes: the two core-semantics facts EVERY phase of the V4-UNIQUE refactoring leans on,
/// exercised the way Identity actually runs — inside an explicit redb transaction
/// (<c>WithRedbTx</c> = <c>Transacted(Suppress)</c> + <c>BeginRedbTransaction</c>, which is
/// <see cref="redb.Core.Data.IRedbContext.BeginTransactionAsync"/> underneath). The core's own
/// <c>UniqueKeyTestsBase</c>/<c>ValueUniqueTestsBase</c> cover the untransacted surface; these two
/// pin the transacted one and stay as permanent regression tests.
/// </summary>
public sealed class V4UniqueTxSemanticsTests : IAsyncLifetime
{
    private ServiceProvider _sp = null!;

    public async Task InitializeAsync()
    {
        var config = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json")
            .Build();
        var pgCs = config.GetConnectionString("Postgres")
            ?? throw new InvalidOperationException("ConnectionStrings:Postgres not found");

        var sc = new ServiceCollection();
        sc.AddLogging(b => b.SetMinimumLevel(LogLevel.Warning));
        sc.AddRedbForTests(pgCs);
        _sp = sc.BuildServiceProvider();

        await using var scope = _sp.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        try { await redb.InitializeAsync(ensureCreated: true); }
        catch { await redb.InitializeAsync(); }
        await redb.SyncSchemeAsync<V4UniqueProbeProps>();
    }

    public async Task DisposeAsync() => await _sp.DisposeAsync();

    [Fact]
    public async Task GetByUnique_InsideExplicitRedbTx_SeesOwnUncommittedWrite_AndRollbackErasesIt()
    {
        await using var scope = _sp.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var code = $"probe-tx-{Guid.NewGuid():N}";

        var tx = await redb.Context.BeginTransactionAsync();
        long id;
        try
        {
            id = await redb.SaveAsync(new RedbObject<V4UniqueProbeProps>(
                new V4UniqueProbeProps { Code = code, Note = "uncommitted" })
            { name = code });

            var seen = await redb.GetByUniqueAsync<V4UniqueProbeProps>(p => p.Code, code);
            seen.Should().NotBeNull(
                "a point probe on the same service inside the same open redb transaction " +
                "must see the transaction's own uncommitted write — every Identity check-then-act " +
                "flow inside WithRedbTx depends on this");
            seen!.Id.Should().Be(id);
        }
        finally
        {
            await tx.RollbackAsync();
        }

        var afterRollback = await redb.GetByUniqueAsync<V4UniqueProbeProps>(p => p.Code, code);
        afterRollback.Should().BeNull("the write was rolled back with the transaction");
    }

    [Fact]
    public async Task DuplicateKey_InsideExplicitRedbTx_IsTyped_TxRollsBack_ServiceStaysUsable()
    {
        var code = $"probe-dup-{Guid.NewGuid():N}";

        // Committed winner, its own scope (committed state must survive the loser's rollback).
        await using (var setup = _sp.CreateAsyncScope())
        {
            var redbSetup = setup.ServiceProvider.GetRequiredService<IRedbService>();
            await redbSetup.SaveAsync(new RedbObject<V4UniqueProbeProps>(
                new V4UniqueProbeProps { Code = code, Note = "winner" })
            { name = code });
        }

        await using var scope = _sp.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();

        var tx = await redb.Context.BeginTransactionAsync();
        try
        {
            var act = async () => await redb.SaveAsync(new RedbObject<V4UniqueProbeProps>(
                new V4UniqueProbeProps { Code = code, Note = "loser" })
            { name = code + "-loser" });

            await act.Should().ThrowAsync<RedbUniqueViolationException>(
                "inside an explicit redb transaction the violation must surface as the one typed " +
                "exception, exactly as untransacted (core changelog, P7) — Identity's 409 mapping " +
                "hangs on this");
        }
        finally
        {
            await tx.RollbackAsync();
        }

        // After the rollback the same scoped service must be fully usable (PG aborts the tx on
        // error until rollback; a poisoned connection here would break every WithRedbTx retry).
        var winner = await redb.GetByUniqueAsync<V4UniqueProbeProps>(p => p.Code, code);
        winner.Should().NotBeNull("the committed winner is untouched by the loser's rollback");
        winner!.Props.Note.Should().Be("winner");

        var other = $"probe-dup-{Guid.NewGuid():N}";
        var otherId = await redb.SaveAsync(new RedbObject<V4UniqueProbeProps>(
            new V4UniqueProbeProps { Code = other, Note = "post-rollback" })
        { name = other });
        otherId.Should().BeGreaterThan(0, "a fresh key saves normally after the rolled-back violation");
    }
}
