using System.Collections.Immutable;
using FluentAssertions;
using Xunit;
using OpenIddict.Abstractions;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;
using redb.Identity.Core.Stores;
using redb.Identity.Tests.Infrastructure;

namespace redb.Identity.Tests.Stores;

[Collection("Postgres")]
public class AuthorizationStoreTests
{
    private readonly RedbAuthorizationStore _store;
    private readonly RedbApplicationStore _appStore;
    private readonly PostgresFixture _fixture;

    public AuthorizationStoreTests(PostgresFixture fixture)
    {
        _fixture = fixture;
        _store = new RedbAuthorizationStore(fixture.Redb);
        _appStore = new RedbApplicationStore(fixture.Redb);
    }

    private async Task<RedbObject<ApplicationProps>> CreateTestAppAsync()
    {
        var app = new RedbObject<ApplicationProps>
        {
            name = $"auth-test-app-{Guid.NewGuid():N}",
            Props = new ApplicationProps { ClientId = $"auth-app-{Guid.NewGuid():N}", ClientType = "confidential" }
        };
        await _appStore.CreateAsync(app, CancellationToken.None);
        return app;
    }

    private static RedbObject<AuthorizationProps> MakeAuth(long appId, Guid? subjectGuid = null) =>
        new()
        {
            value_guid = subjectGuid ?? Guid.NewGuid(),
            Props = new AuthorizationProps
            {
                ApplicationObjectId = appId,
                Status = OpenIddictConstants.Statuses.Valid,
                Type = OpenIddictConstants.AuthorizationTypes.Permanent,
                Scopes = ["openid", "profile"]
            }
        };

    [Fact]
    public async Task CreateAsync_AssignsId()
    {
        var app = await CreateTestAppAsync();
        var auth = MakeAuth(app.id);

        await _store.CreateAsync(auth, CancellationToken.None);

        auth.id.Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task FindByIdAsync_ReturnsCreatedEntity()
    {
        var app = await CreateTestAppAsync();
        var auth = MakeAuth(app.id);
        await _store.CreateAsync(auth, CancellationToken.None);

        var found = await _store.FindByIdAsync(auth.id.ToString(), CancellationToken.None);

        found.Should().NotBeNull();
        found!.Props.Status.Should().Be(OpenIddictConstants.Statuses.Valid);
        found.Props.ApplicationObjectId.Should().Be(app.id);
    }

    [Fact]
    public async Task FindByApplicationIdAsync_ReturnsMatchingAuths()
    {
        var app = await CreateTestAppAsync();
        var auth = MakeAuth(app.id);
        await _store.CreateAsync(auth, CancellationToken.None);

        var results = new List<RedbObject<AuthorizationProps>>();
        await foreach (var r in _store.FindByApplicationIdAsync(app.id.ToString(), CancellationToken.None))
            results.Add(r);

        results.Should().Contain(r => r.id == auth.id);
    }

    [Fact]
    public async Task FindBySubjectAsync_ReturnsMatchingAuths()
    {
        var app = await CreateTestAppAsync();
        var subjectGuid = Guid.NewGuid();
        var auth = MakeAuth(app.id, subjectGuid);
        await _store.CreateAsync(auth, CancellationToken.None);

        var results = new List<RedbObject<AuthorizationProps>>();
        await foreach (var r in _store.FindBySubjectAsync(subjectGuid.ToString("D"), CancellationToken.None))
            results.Add(r);

        results.Should().Contain(r => r.id == auth.id);
    }

    [Fact]
    public async Task FindAsync_MultiFilter()
    {
        var app = await CreateTestAppAsync();
        var subjectGuid = Guid.NewGuid();
        var auth = MakeAuth(app.id, subjectGuid);
        auth.Props.Status = OpenIddictConstants.Statuses.Valid;
        auth.Props.Type = OpenIddictConstants.AuthorizationTypes.Permanent;
        auth.Props.Scopes = ["openid", "profile", "email"];
        await _store.CreateAsync(auth, CancellationToken.None);

        // Filter by subject + client + status + type + scopes subset
        var results = new List<RedbObject<AuthorizationProps>>();
        await foreach (var r in _store.FindAsync(
            subjectGuid.ToString("D"),
            app.id.ToString(),
            OpenIddictConstants.Statuses.Valid,
            OpenIddictConstants.AuthorizationTypes.Permanent,
            ImmutableArray.Create("openid", "profile"),
            CancellationToken.None))
        {
            results.Add(r);
        }

        results.Should().Contain(r => r.id == auth.id);
    }

    [Fact]
    public async Task FindAsync_ScopeSubsetFilter_ExcludesNonMatching()
    {
        var app = await CreateTestAppAsync();
        var subjectGuid = Guid.NewGuid();
        var auth = MakeAuth(app.id, subjectGuid);
        auth.Props.Scopes = ["openid"];
        await _store.CreateAsync(auth, CancellationToken.None);

        // Require both openid + profile, but entity only has openid
        var results = new List<RedbObject<AuthorizationProps>>();
        await foreach (var r in _store.FindAsync(
            subjectGuid.ToString("D"), app.id.ToString(),
            null, null,
            ImmutableArray.Create("openid", "profile"),
            CancellationToken.None))
        {
            results.Add(r);
        }

        results.Should().NotContain(r => r.id == auth.id);
    }

    [Fact]
    public async Task RevokeAsync_ChangesStatusToRevoked()
    {
        var app = await CreateTestAppAsync();
        var subjectGuid = Guid.NewGuid();
        var auth = MakeAuth(app.id, subjectGuid);
        await _store.CreateAsync(auth, CancellationToken.None);

        var revoked = await _store.RevokeAsync(
            subjectGuid.ToString("D"), app.id.ToString(), null, null, CancellationToken.None);

        revoked.Should().BeGreaterOrEqualTo(1);

        var found = await _store.FindByIdAsync(auth.id.ToString(), CancellationToken.None);
        found!.Props.Status.Should().Be(OpenIddictConstants.Statuses.Revoked);
    }

    [Fact]
    public async Task DeleteAsync_RemovesEntity()
    {
        var app = await CreateTestAppAsync();
        var auth = MakeAuth(app.id);
        await _store.CreateAsync(auth, CancellationToken.None);

        await _store.DeleteAsync(auth, CancellationToken.None);

        var found = await _store.FindByIdAsync(auth.id.ToString(), CancellationToken.None);
        found.Should().BeNull();
    }

    [Fact]
    public async Task UpdateAsync_StaleHash_ThrowsConcurrencyException()
    {
        var app = await CreateTestAppAsync();
        var auth = MakeAuth(app.id);
        await _store.CreateAsync(auth, CancellationToken.None);

        // Optimistic concurrency is a cross-REQUEST contract: two callers each in their
        // own request scope load the same row, mutate independently, race to UpdateAsync.
        // We model that with two RedbAuthorizationStore instances so each has its own
        // per-request _idCache. Using `_store` for both copies would return the same
        // cached reference (CreateAsync populated the cache), making the two "copies"
        // aliases of one object — the test would no longer be checking concurrency at
        // all because mutating copy2 also mutates copy1.
        var storeA = new RedbAuthorizationStore(_fixture.Redb);
        var storeB = new RedbAuthorizationStore(_fixture.Redb);
        var copy1 = (await storeA.FindByIdAsync(auth.id.ToString(), CancellationToken.None))!;
        var copy2 = (await storeB.FindByIdAsync(auth.id.ToString(), CancellationToken.None))!;

        copy1.Props.Status = OpenIddictConstants.Statuses.Revoked;
        await storeA.UpdateAsync(copy1, CancellationToken.None);

        copy2.Props.Type = OpenIddictConstants.AuthorizationTypes.AdHoc;
        Func<Task> act = async () => await storeB.UpdateAsync(copy2, CancellationToken.None);
        await act.Should().ThrowAsync<OpenIddictExceptions.ConcurrencyException>();
    }

    [Fact]
    public async Task GettersSetters_Roundtrip()
    {
        var app = await CreateTestAppAsync();
        var auth = await _store.InstantiateAsync(CancellationToken.None);
        var ct = CancellationToken.None;
        var subjectGuid = Guid.NewGuid();
        var subjectStr = subjectGuid.ToString("D");

        await _store.SetApplicationIdAsync(auth, app.id.ToString(), ct);
        await _store.SetSubjectAsync(auth, subjectStr, ct);
        await _store.SetStatusAsync(auth, OpenIddictConstants.Statuses.Valid, ct);
        await _store.SetTypeAsync(auth, OpenIddictConstants.AuthorizationTypes.Permanent, ct);
        await _store.SetScopesAsync(auth, ImmutableArray.Create("openid", "email"), ct);

        (await _store.GetApplicationIdAsync(auth, ct)).Should().Be(app.id.ToString());
        (await _store.GetSubjectAsync(auth, ct)).Should().Be(subjectStr);
        (await _store.GetStatusAsync(auth, ct)).Should().Be(OpenIddictConstants.Statuses.Valid);
        (await _store.GetTypeAsync(auth, ct)).Should().Be(OpenIddictConstants.AuthorizationTypes.Permanent);
        (await _store.GetScopesAsync(auth, ct)).Should().BeEquivalentTo(new[] { "openid", "email" });
    }

    [Fact]
    public async Task CountAsync_IncludesCreatedEntities()
    {
        var before = await _store.CountAsync(CancellationToken.None);

        var app = await CreateTestAppAsync();
        var auth = MakeAuth(app.id);
        await _store.CreateAsync(auth, CancellationToken.None);

        var after = await _store.CountAsync(CancellationToken.None);
        after.Should().BeGreaterThan(before);
    }
}
