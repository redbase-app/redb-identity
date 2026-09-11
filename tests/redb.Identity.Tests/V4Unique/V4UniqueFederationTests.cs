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
/// Ф2 of the V4-UNIQUE refactoring (doc/v4/02): the federation schemes get their FIRST real
/// uniqueness — their XML docs used to promise a partial unique index that no code created.
///
/// <para>
/// Red-before protocol: the storage-level invariant "one external identity — one link row"
/// was verified RED on the pre-Ф2 code in a worktree using the old writing shape (name/key/
/// value_string, no LinkKey — the property did not exist): two identical links saved fine.
/// Here the same invariant is enforced through <c>[RedbUnique]</c> LinkKey / ProviderId.
/// </para>
/// </summary>
public sealed class V4UniqueFederationTests : IAsyncLifetime
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
        await redb.SyncSchemeAsync<FederatedIdentityProps>();
        await redb.SyncSchemeAsync<FederationProviderProps>();
    }

    public async Task DisposeAsync() => await _sp.DisposeAsync();

    [Fact]
    public async Task Duplicate_LinkKey_IsRejected_OneExternalIdentityOneRow()
    {
        using var scope = _sp.CreateScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var sub = Guid.NewGuid().ToString("N");
        var linkKey = FederatedIdentityProps.MakeLinkKey("google", sub);

        var winner = new RedbObject<FederatedIdentityProps>(new FederatedIdentityProps
        { ProviderId = "google", ExternalSub = sub, LinkKey = linkKey });
        winner.name = linkKey;
        winner.key = 1001;
        await redb.SaveAsync(winner);

        var loser = new RedbObject<FederatedIdentityProps>(new FederatedIdentityProps
        { ProviderId = "google", ExternalSub = sub, LinkKey = linkKey });
        loser.name = linkKey;
        loser.key = 2002; // ANOTHER user grabbing the same external identity

        var act = async () => await redb.SaveAsync(loser);
        await act.Should().ThrowAsync<RedbUniqueViolationException>(
            "pre-Ф2 nothing enforced this: the promised index never existed and a race "
            + "could link one external identity to two local users");

        var found = await redb.GetByUniqueAsync<FederatedIdentityProps>(p => p.LinkKey, linkKey);
        found!.key.Should().Be(1001, "the first user keeps the identity");
    }

    [Fact]
    public async Task Duplicate_ProviderId_IsRejected()
    {
        using var scope = _sp.CreateScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var providerId = $"prov-{Guid.NewGuid():N}";

        await redb.SaveAsync(new RedbObject<FederationProviderProps>(
            new FederationProviderProps { ProviderId = providerId, Kind = "oidc" })
        { name = providerId });

        var act = async () => await redb.SaveAsync(new RedbObject<FederationProviderProps>(
            new FederationProviderProps { ProviderId = providerId, Kind = "oidc" })
        { name = providerId + "-loser" });
        await act.Should().ThrowAsync<RedbUniqueViolationException>();
    }

    [Fact]
    public async Task SoftDelete_ReleasesLinkKey_UnlinkThenRelinkWorks()
    {
        using var scope = _sp.CreateScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var sub = Guid.NewGuid().ToString("N");
        var linkKey = FederatedIdentityProps.MakeLinkKey("github", sub);

        var link = new RedbObject<FederatedIdentityProps>(new FederatedIdentityProps
        { ProviderId = "github", ExternalSub = sub, LinkKey = linkKey });
        link.name = linkKey;
        link.key = 3003;
        var firstId = await redb.SaveAsync(link);

        (await redb.DeleteAsync(firstId)).Should().BeTrue();

        var relink = new RedbObject<FederatedIdentityProps>(new FederatedIdentityProps
        { ProviderId = "github", ExternalSub = sub, LinkKey = linkKey });
        relink.name = linkKey;
        relink.key = 3003;
        var secondId = await redb.SaveAsync(relink);
        secondId.Should().BeGreaterThan(0,
            "unlink (soft delete) releases the unique key, so the user can relink the same identity");
    }

    [Fact]
    public async Task Backfill_RepairsLegacyLink_AndReportsDuplicateLinks()
    {
        var sub = Guid.NewGuid().ToString("N");
        var legacyKey = FederatedIdentityProps.MakeLinkKey("azure-ad", sub);
        long legacyId, dupId;

        using (var scope = _sp.CreateScope())
        {
            var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();

            // Exactly the pre-V4 writing shape: composite in name/value_string, LinkKey absent.
            var legacy = new RedbObject<FederatedIdentityProps>(new FederatedIdentityProps
            { ProviderId = "azure-ad", ExternalSub = sub });
            legacy.name = legacyKey;
            legacy.key = 4004;
            legacy.value_string = legacyKey;
            legacyId = await redb.SaveAsync(legacy);

            // The pre-Ф2 defect in the flesh: a SECOND row for the same identity, other user.
            var dup = new RedbObject<FederatedIdentityProps>(new FederatedIdentityProps
            { ProviderId = "azure-ad", ExternalSub = sub });
            dup.name = legacyKey;
            dup.key = 5005;
            dup.value_string = legacyKey;
            dupId = await redb.SaveAsync(dup);

            (await redb.GetByUniqueAsync<FederatedIdentityProps>(p => p.LinkKey, legacyKey))
                .Should().BeNull("legacy rows have no unique key before the backfill");
        }

        // Single-scheme gate-free pass — see V4UniqueKeyTests for why (parallel full
        // passes on the shared DB repaired each other's rows).
        await new V4UniqueBackfillListener(_sp).RunMirrorSchemeAsync<FederatedIdentityProps>(
            p => p.LinkKey, (p, v) => p.LinkKey = v, CancellationToken.None);

        using (var scope = _sp.CreateScope())
        {
            var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();

            // Р4(а): one of the two rows won the key; the loser is preserved outside the
            // index and was reported to the operator log — a duplicated federated link is
            // a potential account-takeover and is never resolved silently.
            var winner = await redb.GetByUniqueAsync<FederatedIdentityProps>(p => p.LinkKey, legacyKey);
            winner.Should().NotBeNull("the backfill repaired the legacy mirror into LinkKey");
            new[] { legacyId, dupId }.Should().Contain(winner!.Id);
            (await redb.LoadAsync<FederatedIdentityProps>(legacyId)).Should().NotBeNull();
            (await redb.LoadAsync<FederatedIdentityProps>(dupId)).Should().NotBeNull();
        }
    }
}
