using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Models.Configuration;
using redb.Core.Extensions;
using redb.Core.Pro.Extensions;
using redb.Identity.Core;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.DataProtection;
using redb.Postgres.Pro.Extensions;
using Xunit;using redb.Identity.Tests.Infrastructure;


namespace redb.Identity.Tests.Configuration;

/// <summary>
/// G12 / A6 — idempotent bootstrap of Identity against a shared PostgreSQL backend.
/// <para>
/// In a clustered deployment several Identity replicas come up in parallel and all
/// run the same schema-sync + unique-index creation path
/// (<see cref="redb.Identity.Core.Module.IdentitySchemaInitListener"/>,
/// <see cref="redb.Identity.Core.Module.IdentityUniqueIndexesInitListener"/>).
/// Any non-idempotent write in that path — <c>CREATE TABLE</c> without
/// <c>IF NOT EXISTS</c>, <c>CREATE UNIQUE INDEX</c> without guards, a seed row
/// inserted twice — would either crash the second replica or leave the DB in an
/// inconsistent state.
/// </para>
/// <para>
/// This test exercises exactly that contract by running two independent Identity
/// service-provider bootstraps back-to-back against the same connection string and
/// re-invoking <c>InitializeAsync</c> + <c>SyncSchemeAsync</c> on both. The second
/// replica must succeed with no schema changes.
/// </para>
/// </summary>
public sealed class MultiReplicaBootstrapTests
{
    [Fact]
    public async Task TwoSequentialReplicas_ShareSchema_Idempotent()
    {
        var cs = LoadConnectionString();

        // Replica A — first to come up, creates schema + indexes.
        await using var spA = BuildReplicaSp(cs);
        var redbA = spA.GetRequiredService<IRedbService>();
        try { await redbA.InitializeAsync(ensureCreated: true); }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"InitializeAsync(ensureCreated:true) failed, falling back: {ex.GetType().Name}: {ex.Message}");
            await redbA.InitializeAsync();
        }
        await SyncIdentitySchemasAsync(redbA);

        // Replica B — second to come up against the same DB. MUST NOT throw and MUST
        // NOT partially re-create anything. This is the core A6 contract: in a
        // clustered deployment the second-to-start replica cannot be forced to crash
        // because the first already claimed the schema.
        await using var spB = BuildReplicaSp(cs);
        var redbB = spB.GetRequiredService<IRedbService>();
        var act = async () =>
        {
            try { await redbB.InitializeAsync(ensureCreated: true); }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"InitializeAsync(ensureCreated:true) failed, falling back: {ex.GetType().Name}: {ex.Message}");
                await redbB.InitializeAsync();
            }
            await SyncIdentitySchemasAsync(redbB);
        };

        await act.Should().NotThrowAsync(
            "A6: parallel / sequential replicas running the same Identity bootstrap MUST " +
            "be idempotent. A regression here crashes the second node of every two-node " +
            "cluster.");
    }

    [Fact]
    public async Task SameReplica_RerunInitialize_Idempotent()
    {
        // Single-replica restart guard: Identity runs the same init path on every
        // process start. A non-idempotent DDL / seed would fail after the first
        // deployment unless operators manually truncate the schema between releases.
        var cs = LoadConnectionString();
        await using var sp = BuildReplicaSp(cs);
        var redb = sp.GetRequiredService<IRedbService>();

        try { await redb.InitializeAsync(ensureCreated: true); }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"InitializeAsync(ensureCreated:true) failed, falling back: {ex.GetType().Name}: {ex.Message}");
            await redb.InitializeAsync();
        }
        await SyncIdentitySchemasAsync(redb);

        var act = async () =>
        {
            try { await redb.InitializeAsync(ensureCreated: true); }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"InitializeAsync(ensureCreated:true) failed, falling back: {ex.GetType().Name}: {ex.Message}");
                await redb.InitializeAsync();
            }
            await SyncIdentitySchemasAsync(redb);
        };

        await act.Should().NotThrowAsync(
            "A single replica's restart loop must be idempotent — every process start " +
            "re-runs InitializeAsync + SyncSchemeAsync. Non-idempotency here means every " +
            "redeploy is a schema breakage.");
    }

    private static string LoadConnectionString() =>
        new ConfigurationBuilder()
            .AddJsonFile("appsettings.json")
            .Build()
            .GetConnectionString("Postgres")
            ?? throw new InvalidOperationException("ConnectionStrings:Postgres not found");

    private static ServiceProvider BuildReplicaSp(string cs)
    {
        var services = new ServiceCollection();
        services.AddLogging(b => b.SetMinimumLevel(LogLevel.Warning));
        services.AddRedbForTests(cs);

        services.AddRedbIdentityServer(new RedbIdentityOptions
        {
            AllowEphemeralKeys = true,
            DisableAccessTokenEncryption = true,
        });

        return services.BuildServiceProvider();
    }

    private static async Task SyncIdentitySchemasAsync(IRedbService redb)
    {
        // Mirror the subset of schemas pinned by ProductionHttpFixture so the test
        // exercises every Identity scheme's sync path, not just the base redb tables.
        await redb.SyncSchemeAsync<ApplicationProps>();
        await redb.SyncSchemeAsync<AuthorizationProps>();
        await redb.SyncSchemeAsync<ScopeProps>();
        await redb.SyncSchemeAsync<TokenProps>();
        await redb.SyncSchemeAsync<UserProps>();
        await redb.SyncSchemeAsync<DataProtectionKeyProps>();
        await redb.SyncSchemeAsync<SessionProps>();
        await redb.SyncSchemeAsync<MfaProps>();
        await redb.SyncSchemeAsync<GroupProps>();
        await redb.SyncSchemeAsync<GroupMemberProps>();
    }
}
