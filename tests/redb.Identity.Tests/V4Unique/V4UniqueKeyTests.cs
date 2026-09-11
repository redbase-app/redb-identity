using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Exceptions;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;
using redb.Identity.Core.Module;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.V4Unique;

/// <summary>
/// Ф1 of the V4-UNIQUE refactoring (doc/v4/01): the four OAuth keys are enforced by the
/// database via <c>[RedbUnique]</c> on every provider.
///
/// <para>
/// Red-before protocol: on the pre-Ф1 code every duplicate test here is RED on ALL THREE
/// providers — the keys were <c>[RedbIgnore]</c> phantoms mirrored into
/// <c>_objects.value_string</c>, so a plain <c>SaveAsync</c> wrote no key and nothing
/// collided (the old artificial indexes guarded only the mirror column, and on MSSQL the
/// three <c>value_string</c> indexes did not exist at all). Verified red in a worktree at
/// the pre-Ф1 commit, full-suite run (see doc/v4/01 §5).
/// </para>
/// </summary>
public sealed class V4UniqueKeyTests : IAsyncLifetime
{
    private ServiceProvider _sp = null!;
    private readonly Xunit.Abstractions.ITestOutputHelper _out;

    public V4UniqueKeyTests(Xunit.Abstractions.ITestOutputHelper output) => _out = output;

    public async Task InitializeAsync()
    {
        var config = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json")
            .Build();
        var pgCs = config.GetConnectionString("Postgres")
            ?? throw new InvalidOperationException("ConnectionStrings:Postgres not found");

        var sc = new ServiceCollection();
        // Debug + xunit sink: the backfill listener swallows scheme-level failures into the
        // log by design (an unfilled scheme must not kill the host), so a provider-specific
        // failure is only diagnosable if its counters and exception reach the test output.
        sc.AddLogging(b => b.SetMinimumLevel(LogLevel.Debug).AddProvider(new XunitTestLoggerProvider(_out)));
        sc.AddRedbForTests(pgCs);
        _sp = sc.BuildServiceProvider();

        await using var scope = _sp.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        try { await redb.InitializeAsync(ensureCreated: true); }
        catch { await redb.InitializeAsync(); }
        await redb.SyncSchemeAsync<ApplicationProps>();
        await redb.SyncSchemeAsync<ScopeProps>();
        await redb.SyncSchemeAsync<ClaimScopeProps>();
        await redb.SyncSchemeAsync<TokenProps>();
    }

    public async Task DisposeAsync() => await _sp.DisposeAsync();

    private IRedbService Redb(IServiceScope scope)
        => scope.ServiceProvider.GetRequiredService<IRedbService>();

    // ── duplicates rejected, lookup finds the winner ─────────────────────────────

    [Fact]
    public async Task Duplicate_ClientId_IsRejected_AndLookupFindsTheWinner()
    {
        using var scope = _sp.CreateScope();
        var redb = Redb(scope);
        var clientId = $"v4-app-{Guid.NewGuid():N}";

        var winnerId = await redb.SaveAsync(new RedbObject<ApplicationProps>(
            new ApplicationProps { ClientId = clientId, ClientType = "public" })
        { name = "winner" });

        var act = async () => await redb.SaveAsync(new RedbObject<ApplicationProps>(
            new ApplicationProps { ClientId = clientId, ClientType = "public" })
        { name = "loser" });
        await act.Should().ThrowAsync<RedbUniqueViolationException>(
            "pre-Ф1 the ClientId was a [RedbIgnore] phantom and this save went through "
            + "on every provider (on MSSQL even the mirror index never existed)");

        var found = await redb.GetByUniqueAsync<ApplicationProps>(p => p.ClientId, clientId);
        found.Should().NotBeNull();
        found!.Id.Should().Be(winnerId);
        found.Props.ClientId.Should().Be(clientId, "the key is a stored prop now, no Hydrate needed");
    }

    [Fact]
    public async Task Duplicate_ScopeName_IsRejected()
    {
        using var scope = _sp.CreateScope();
        var redb = Redb(scope);
        var name = $"v4-scope-{Guid.NewGuid():N}";

        await redb.SaveAsync(new RedbObject<ScopeProps>(
            new ScopeProps { ScopeName = name }) { name = name });

        var act = async () => await redb.SaveAsync(new RedbObject<ScopeProps>(
            new ScopeProps { ScopeName = name }) { name = name + "-loser" });
        await act.Should().ThrowAsync<RedbUniqueViolationException>();
    }

    [Fact]
    public async Task Duplicate_ClaimScopeName_IsRejected_ThePhantomIndexHole()
    {
        using var scope = _sp.CreateScope();
        var redb = Redb(scope);
        var name = $"v4-claimscope-{Guid.NewGuid():N}";

        await redb.SaveAsync(new RedbObject<ClaimScopeProps>(
            new ClaimScopeProps { ScopeName = name }) { name = name });

        var act = async () => await redb.SaveAsync(new RedbObject<ClaimScopeProps>(
            new ClaimScopeProps { ScopeName = name }) { name = name + "-loser" });
        await act.Should().ThrowAsync<RedbUniqueViolationException>(
            "the ClaimScope XML doc used to PROMISE a partial unique index that no code ever "
            + "created — duplicates were possible on every provider until Ф1");
    }

    [Fact]
    public async Task Duplicate_TokenReferenceId_IsRejected_NullsDoNotParticipate()
    {
        using var scope = _sp.CreateScope();
        var redb = Redb(scope);
        var refId = $"v4-ref-{Guid.NewGuid():N}";

        await redb.SaveAsync(new RedbObject<TokenProps>(
            new TokenProps { ReferenceId = refId, Type = "refresh_token", Status = "valid" })
        { name = "tok-1" });

        var act = async () => await redb.SaveAsync(new RedbObject<TokenProps>(
            new TokenProps { ReferenceId = refId, Type = "refresh_token", Status = "valid" })
        { name = "tok-2" });
        await act.Should().ThrowAsync<RedbUniqueViolationException>();

        // Non-reference tokens (ReferenceId = null) must not collide with each other.
        var idA = await redb.SaveAsync(new RedbObject<TokenProps>(
            new TokenProps { Type = "access_token", Status = "valid" }) { name = "null-a" });
        var idB = await redb.SaveAsync(new RedbObject<TokenProps>(
            new TokenProps { Type = "access_token", Status = "valid" }) { name = "null-b" });
        idA.Should().BeGreaterThan(0);
        idB.Should().BeGreaterThan(0);
    }

    // ── soft delete releases the key (parity with the old partial index) ─────────

    [Fact]
    public async Task SoftDelete_ReleasesClientId_SameKeyCanBeRecreated()
    {
        using var scope = _sp.CreateScope();
        var redb = Redb(scope);
        var clientId = $"v4-del-{Guid.NewGuid():N}";

        var firstId = await redb.SaveAsync(new RedbObject<ApplicationProps>(
            new ApplicationProps { ClientId = clientId }) { name = "first" });
        (await redb.DeleteAsync(firstId)).Should().BeTrue();

        var secondId = await redb.SaveAsync(new RedbObject<ApplicationProps>(
            new ApplicationProps { ClientId = clientId }) { name = "second" });
        secondId.Should().BeGreaterThan(0,
            "soft delete releases the unique key in the same transaction (core decision 9)");
        secondId.Should().NotBe(firstId);
    }

    // ── transition backfill (doc/v4/04 §3) ───────────────────────────────────────

    [Fact]
    public async Task Backfill_RepairsLegacyMirrorRows_AndReportsDuplicates()
    {
        var legacyKey = $"v4-legacy-{Guid.NewGuid():N}";
        var dupKey = $"v4-legacydup-{Guid.NewGuid():N}";
        long legacyId, dupAId, dupBId;

        // Legacy shape: mirror set, Props key empty — exactly what pre-V4 code persisted
        // (the prop was [RedbIgnore], so nothing ever reached _values).
        using (var scope = _sp.CreateScope())
        {
            var redb = Redb(scope);
            var legacy = new RedbObject<ApplicationProps>(new ApplicationProps { ClientId = null })
            { name = "legacy" };
            legacy.value_string = legacyKey;
            legacyId = await redb.SaveAsync(legacy);

            var dupA = new RedbObject<ApplicationProps>(new ApplicationProps()) { name = "dup-a" };
            dupA.value_string = dupKey;
            dupAId = await redb.SaveAsync(dupA);
            var dupB = new RedbObject<ApplicationProps>(new ApplicationProps()) { name = "dup-b" };
            dupB.value_string = dupKey;
            dupBId = await redb.SaveAsync(dupB);

            // Invisible to the unique lookup before the backfill.
            (await redb.GetByUniqueAsync<ApplicationProps>(p => p.ClientId, legacyKey))
                .Should().BeNull("a legacy row has no _values value and no unique key yet");
        }

        // Single-scheme gate-free pass: on the process-shared SQLite database, parallel
        // test classes each running a FULL pass repaired each other's rows concurrently
        // (false-duplicate collisions, stale-snapshot overwrites) — so every backfill test
        // repairs exactly its own scheme.
        var clean = await new V4UniqueBackfillListener(_sp).RunMirrorSchemeAsync<ApplicationProps>(
            p => p.ClientId, (p, v) => p.ClientId = v, CancellationToken.None);
        clean.Should().BeTrue(
            "the scheme pass must not abort on a scheme-level exception (duplicates are reported, not "
            + "thrown) — the listener's log in the test output names the exception when it does");

        using (var scope = _sp.CreateScope())
        {
            var redb = Redb(scope);

            var repaired = await redb.GetByUniqueAsync<ApplicationProps>(p => p.ClientId, legacyKey);
            repaired.Should().NotBeNull("the backfill copied the mirror into Props and re-saved");
            repaired!.Id.Should().Be(legacyId);
            repaired.Props.ClientId.Should().Be(legacyKey);

            // Р4(а): exactly one of the two duplicate rows won the key; the loser survives
            // outside the index for manual review, nothing was deleted silently.
            var dupWinner = await redb.GetByUniqueAsync<ApplicationProps>(p => p.ClientId, dupKey);
            dupWinner.Should().NotBeNull();
            new[] { dupAId, dupBId }.Should().Contain(dupWinner!.Id);
            (await redb.LoadAsync<ApplicationProps>(dupAId)).Should().NotBeNull();
            (await redb.LoadAsync<ApplicationProps>(dupBId)).Should().NotBeNull();

            // Idempotence: a second run converges to a no-op and changes nothing.
            await new V4UniqueBackfillListener(_sp).RunMirrorSchemeAsync<ApplicationProps>(
                p => p.ClientId, (p, v) => p.ClientId = v, CancellationToken.None);
            (await redb.GetByUniqueAsync<ApplicationProps>(p => p.ClientId, dupKey))!
                .Id.Should().Be(dupWinner.Id);
        }
    }
}
