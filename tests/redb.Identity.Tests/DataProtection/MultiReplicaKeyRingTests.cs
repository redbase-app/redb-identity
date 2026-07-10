using System.Collections.Immutable;
using System.Xml.Linq;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Models.Configuration;
using redb.Core.Extensions;
using redb.Core.Pro.Extensions;
using redb.Identity.Core.DataProtection;
using redb.Identity.DataProtection;
using redb.Identity.Core.Models;
using redb.Postgres.Pro.Extensions;
using Xunit;using redb.Identity.Tests.Infrastructure;


namespace redb.Identity.Tests.DataProtection;

/// <summary>
/// G1 — multi-replica DataProtection key-ring sanity.
/// <para>
/// Two independent <see cref="ServiceProvider"/> instances (= two replicas in the same cluster)
/// share one PostgreSQL <c>DataProtectionKeyProps</c> PROPS store. The test verifies the
/// contract underpinning A1: <see cref="RedbXmlRepository"/> keeps an in-process snapshot
/// and the periodic refresh (emulated here inline, same query/replace logic as
/// <see cref="XmlRepositoryRefreshProcessor"/>) pulls keys authored by the other replica so
/// that cookies/tokens encrypted on one node are decryptable on the other.
/// </para>
/// </summary>
public class MultiReplicaKeyRingTests : IAsyncLifetime
{
    private ServiceProvider _replicaA = null!;
    private ServiceProvider _replicaB = null!;
    private RedbXmlRepository _repoA = null!;
    private RedbXmlRepository _repoB = null!;

    public async Task InitializeAsync()
    {
        var config = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json")
            .Build();
        var pgCs = config.GetConnectionString("Postgres")
            ?? throw new InvalidOperationException("ConnectionStrings:Postgres not found");

        // When running under SQLite (the default test provider) we need BOTH
        // replicas to point at the same physical file so the second instance
        // sees what the first wrote. AddRedbForTests builds a fresh per-call
        // SQLite path by default — pin the env var to a single scratch file
        // for the duration of this test so both calls converge.
        var sqliteScratch = TestRedbSetup.SelectedProvider == TestRedbSetup.Provider.Sqlite
            ? TestRedbSetup.CreateSqliteScratchPath()
            : null;
        if (sqliteScratch is not null)
            Environment.SetEnvironmentVariable("REDB_SQLITE_CS",
                TestRedbSetup.BuildSqliteConnectionString(sqliteScratch));

        try
        {
            _replicaA = BuildReplica(pgCs);
            _replicaB = BuildReplica(pgCs);
        }
        finally
        {
            // The pinned env var is process-wide; clear it as soon as both
            // service providers have captured their connection string.
            if (sqliteScratch is not null)
                Environment.SetEnvironmentVariable("REDB_SQLITE_CS", null);
        }

        // Replica A bootstraps the schema once. Replica B reuses the same physical DB.
        var redbA = _replicaA.GetRequiredService<IRedbService>();
        try { await redbA.InitializeAsync(ensureCreated: true); }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"InitializeAsync(ensureCreated:true) failed, falling back: {ex.GetType().Name}: {ex.Message}");
            await redbA.InitializeAsync();
        }
        await redbA.SyncSchemeAsync<DataProtectionKeyProps>();
        await redbA.InitializeTypeRegistryAsync();

        var redbB = _replicaB.GetRequiredService<IRedbService>();
        await redbB.InitializeAsync();
        await redbB.InitializeTypeRegistryAsync();

        _repoA = new RedbXmlRepository(_replicaA.GetRequiredService<IServiceScopeFactory>());
        _repoB = new RedbXmlRepository(_replicaB.GetRequiredService<IServiceScopeFactory>());

        // Seed both snapshots from DB (what RedbXmlRepositoryInitListener does at startup).
        await RefreshAsync(_replicaA, _repoA);
        await RefreshAsync(_replicaB, _repoB);
    }

    public async Task DisposeAsync()
    {
        await _replicaA.DisposeAsync();
        await _replicaB.DisposeAsync();
    }

    private static ServiceProvider BuildReplica(string cs)
    {
        var sc = new ServiceCollection();
        sc.AddLogging(b => b.SetMinimumLevel(LogLevel.Warning));
        sc.AddRedbForTests(cs);
        return sc.BuildServiceProvider();
    }

    /// <summary>
    /// Mirrors <see cref="XmlRepositoryRefreshProcessor.Process"/> — pulls all persisted keys
    /// and overwrites the in-process snapshot. Keeping this identical to production logic
    /// means any change there must also update this helper (guarded by the test itself).
    /// </summary>
    private static async Task RefreshAsync(IServiceProvider sp, RedbXmlRepository repo)
    {
        await using var scope = sp.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var keys = await redb.Query<DataProtectionKeyProps>().ToListAsync();
        var builder = ImmutableArray.CreateBuilder<XElement>(keys.Count);
        foreach (var k in keys)
            if (!string.IsNullOrEmpty(k.Props.XmlContent))
                builder.Add(XElement.Parse(k.Props.XmlContent));
        repo.ReplaceSnapshot(builder.ToImmutable());
    }

    [Fact]
    public async Task KeyWrittenOnReplicaA_VisibleOnReplicaB_AfterRefresh()
    {
        var keyId = $"g1-xprocess-{Guid.NewGuid()}";
        var element = new XElement("key",
            new XAttribute("id", keyId),
            new XElement("descriptor", "written-by-replica-A"));

        // Pre-refresh: B must not see a key that hasn't been written yet.
        _repoB.GetAllElements().Should().NotContain(
            e => HasId(e, keyId),
            "B's snapshot was seeded before A wrote the new key");

        _repoA.StoreElement(element, $"friendly-{keyId}");

        // Without refresh B still sees its stale snapshot.
        _repoB.GetAllElements().Should().NotContain(
            e => HasId(e, keyId),
            "B is a separate replica with its own snapshot — it must not learn about A's write until it refreshes");

        // After refresh B picks up the key authored by A. This is the cross-replica contract.
        await RefreshAsync(_replicaB, _repoB);
        _repoB.GetAllElements().Should().Contain(
            e => HasId(e, keyId),
            "after a refresh tick the PROPS-backed snapshot must include keys authored by peers");
    }

    [Fact]
    public async Task KeyRotation_OldAndNewCoexist_OnBothReplicas()
    {
        // "Old" key on A — simulates the previous active key.
        var oldId = $"g1-old-{Guid.NewGuid()}";
        _repoA.StoreElement(
            new XElement("key", new XAttribute("id", oldId), new XElement("descriptor", "old")),
            $"old-{oldId}");

        // Fan out to B (initial propagation).
        await RefreshAsync(_replicaB, _repoB);
        _repoB.GetAllElements().Should().Contain(e => HasId(e, oldId));

        // "New" key rotated in on B — simulates a different replica winning the rotation race.
        var newId = $"g1-new-{Guid.NewGuid()}";
        _repoB.StoreElement(
            new XElement("key", new XAttribute("id", newId), new XElement("descriptor", "new")),
            $"new-{newId}");

        // Refresh A: both keys must be visible simultaneously. This is the overlap window
        // where tokens encrypted with the old key are still decryptable by the new replica
        // while new tokens are minted with the rotated key.
        await RefreshAsync(_replicaA, _repoA);

        var snapA = _repoA.GetAllElements();
        snapA.Should().Contain(e => HasId(e, oldId), "old key stays in snapshot during overlap window");
        snapA.Should().Contain(e => HasId(e, newId), "new key authored by peer must be pulled in");

        var snapB = _repoB.GetAllElements();
        snapB.Should().Contain(e => HasId(e, oldId));
        snapB.Should().Contain(e => HasId(e, newId), "B's own write is reflected in its snapshot immediately (ImmutableInterlocked.Update)");
    }

    // Expression-tree-safe helper: FluentAssertions' Contain/NotContain accepts Expression<Func<T,bool>>,
    // which forbids null-conditional operators (CS8072). Keep the null-check explicit.
    private static bool HasId(XElement e, string id)
    {
        var attr = e.Attribute("id");
        return attr != null && attr.Value == id;
    }
}
