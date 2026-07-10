using FluentAssertions;
using Xunit;
using OpenIddict.Abstractions;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;
using redb.Identity.Core.Stores;
using redb.Identity.Tests.Infrastructure;

namespace redb.Identity.Tests.Stores;

[Collection("Postgres")]
public class TokenStoreTests
{
    private readonly RedbTokenStore _store;
    private readonly RedbApplicationStore _appStore;
    private readonly RedbAuthorizationStore _authStore;
    private readonly PostgresFixture _fixture;

    public TokenStoreTests(PostgresFixture fixture)
    {
        _fixture = fixture;
        _store = new RedbTokenStore(fixture.Redb);
        _appStore = new RedbApplicationStore(fixture.Redb);
        _authStore = new RedbAuthorizationStore(fixture.Redb);
    }

    private async Task<RedbObject<ApplicationProps>> CreateTestAppAsync()
    {
        var app = new RedbObject<ApplicationProps>
        {
            name = $"token-test-app-{Guid.NewGuid():N}",
            Props = new ApplicationProps { ClientId = $"tok-{Guid.NewGuid():N}", ClientType = "confidential" }
        };
        await _appStore.CreateAsync(app, CancellationToken.None);
        return app;
    }

    private async Task<RedbObject<AuthorizationProps>> CreateTestAuthAsync(long appId)
    {
        var auth = new RedbObject<AuthorizationProps>
        {
            key = 1,
            Props = new AuthorizationProps
            {
                ApplicationObjectId = appId,
                Status = OpenIddictConstants.Statuses.Valid,
                Type = OpenIddictConstants.AuthorizationTypes.Permanent
            }
        };
        await _authStore.CreateAsync(auth, CancellationToken.None);
        return auth;
    }

    private static RedbObject<TokenProps> MakeToken(long appId, long authId, Guid? subjectGuid = null) =>
        new()
        {
            value_guid = subjectGuid ?? Guid.NewGuid(),
            value_long = appId,
            value_string = $"ref-{Guid.NewGuid():N}",
            note = "{\"test\":true}",
            Props = new TokenProps
            {
                AuthorizationObjectId = authId,
                Status = OpenIddictConstants.Statuses.Valid,
                Type = "access_token"
            }
        };

    [Fact]
    public async Task CreateAsync_AssignsId()
    {
        var app = await CreateTestAppAsync();
        var auth = await CreateTestAuthAsync(app.id);
        var token = MakeToken(app.id, auth.id);

        await _store.CreateAsync(token, CancellationToken.None);
        token.id.Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task FindByIdAsync_ReturnsCreatedEntity()
    {
        var app = await CreateTestAppAsync();
        var auth = await CreateTestAuthAsync(app.id);
        var token = MakeToken(app.id, auth.id);
        await _store.CreateAsync(token, CancellationToken.None);

        var found = await _store.FindByIdAsync(token.id.ToString(), CancellationToken.None);
        found.Should().NotBeNull();
        found!.Props.Status.Should().Be(OpenIddictConstants.Statuses.Valid);
    }

    [Fact]
    public async Task FindByReferenceIdAsync_ReturnsCorrectToken()
    {
        var app = await CreateTestAppAsync();
        var auth = await CreateTestAuthAsync(app.id);
        var token = MakeToken(app.id, auth.id);
        var refId = token.value_string!;
        await _store.CreateAsync(token, CancellationToken.None);

        var found = await _store.FindByReferenceIdAsync(refId, CancellationToken.None);
        found.Should().NotBeNull();
        found!.id.Should().Be(token.id);
    }

    [Fact]
    public async Task FindByApplicationIdAsync_ReturnsMatchingTokens()
    {
        var app = await CreateTestAppAsync();
        var auth = await CreateTestAuthAsync(app.id);
        var token = MakeToken(app.id, auth.id);
        await _store.CreateAsync(token, CancellationToken.None);

        var results = new List<RedbObject<TokenProps>>();
        await foreach (var r in _store.FindByApplicationIdAsync(app.id.ToString(), CancellationToken.None))
            results.Add(r);

        results.Should().Contain(r => r.id == token.id);
    }

    [Fact]
    public async Task FindByAuthorizationIdAsync_ReturnsMatchingTokens()
    {
        var app = await CreateTestAppAsync();
        var auth = await CreateTestAuthAsync(app.id);
        var token = MakeToken(app.id, auth.id);
        await _store.CreateAsync(token, CancellationToken.None);

        var results = new List<RedbObject<TokenProps>>();
        await foreach (var r in _store.FindByAuthorizationIdAsync(auth.id.ToString(), CancellationToken.None))
            results.Add(r);

        results.Should().Contain(r => r.id == token.id);
    }

    [Fact]
    public async Task FindBySubjectAsync_ReturnsMatchingTokens()
    {
        var app = await CreateTestAppAsync();
        var auth = await CreateTestAuthAsync(app.id);
        var subjectGuid = Guid.NewGuid();
        var token = MakeToken(app.id, auth.id, subjectGuid);
        await _store.CreateAsync(token, CancellationToken.None);

        var results = new List<RedbObject<TokenProps>>();
        await foreach (var r in _store.FindBySubjectAsync(subjectGuid.ToString("D"), CancellationToken.None))
            results.Add(r);

        results.Should().Contain(r => r.id == token.id);
    }

    [Fact]
    public async Task FindAsync_MultiFilter()
    {
        var app = await CreateTestAppAsync();
        var auth = await CreateTestAuthAsync(app.id);
        var subjectGuid = Guid.NewGuid();
        var token = MakeToken(app.id, auth.id, subjectGuid);
        await _store.CreateAsync(token, CancellationToken.None);

        var results = new List<RedbObject<TokenProps>>();
        await foreach (var r in _store.FindAsync(
            subjectGuid.ToString("D"), app.id.ToString(),
            OpenIddictConstants.Statuses.Valid,
            "access_token",
            CancellationToken.None))
        {
            results.Add(r);
        }

        results.Should().Contain(r => r.id == token.id);
    }

    [Fact]
    public async Task RevokeByApplicationIdAsync_RevokesMatchingTokens()
    {
        var app = await CreateTestAppAsync();
        var auth = await CreateTestAuthAsync(app.id);
        var token = MakeToken(app.id, auth.id);
        await _store.CreateAsync(token, CancellationToken.None);

        var count = await _store.RevokeByApplicationIdAsync(app.id.ToString(), CancellationToken.None);
        count.Should().BeGreaterOrEqualTo(1);

        var found = await _store.FindByIdAsync(token.id.ToString(), CancellationToken.None);
        found!.Props.Status.Should().Be(OpenIddictConstants.Statuses.Revoked);
    }

    [Fact]
    public async Task RevokeByAuthorizationIdAsync_RevokesMatchingTokens()
    {
        var app = await CreateTestAppAsync();
        var auth = await CreateTestAuthAsync(app.id);
        var token = MakeToken(app.id, auth.id);
        await _store.CreateAsync(token, CancellationToken.None);

        var count = await _store.RevokeByAuthorizationIdAsync(auth.id.ToString(), CancellationToken.None);
        count.Should().BeGreaterOrEqualTo(1);

        var found = await _store.FindByIdAsync(token.id.ToString(), CancellationToken.None);
        found!.Props.Status.Should().Be(OpenIddictConstants.Statuses.Revoked);
    }

    [Fact]
    public async Task RevokeBySubjectAsync_RevokesMatchingTokens()
    {
        var app = await CreateTestAppAsync();
        var auth = await CreateTestAuthAsync(app.id);
        var subjectGuid = Guid.NewGuid();
        var token = MakeToken(app.id, auth.id, subjectGuid);
        await _store.CreateAsync(token, CancellationToken.None);

        var count = await _store.RevokeBySubjectAsync(subjectGuid.ToString("D"), CancellationToken.None);
        count.Should().BeGreaterOrEqualTo(1);

        var found = await _store.FindByIdAsync(token.id.ToString(), CancellationToken.None);
        found!.Props.Status.Should().Be(OpenIddictConstants.Statuses.Revoked);
    }

    [Fact]
    public async Task DeleteAsync_RemovesEntity()
    {
        var app = await CreateTestAppAsync();
        var auth = await CreateTestAuthAsync(app.id);
        var token = MakeToken(app.id, auth.id);
        await _store.CreateAsync(token, CancellationToken.None);

        await _store.DeleteAsync(token, CancellationToken.None);

        var found = await _store.FindByIdAsync(token.id.ToString(), CancellationToken.None);
        found.Should().BeNull();
    }

    [Fact]
    public async Task UpdateAsync_StaleHash_ThrowsConcurrencyException()
    {
        var app = await CreateTestAppAsync();
        var auth = await CreateTestAuthAsync(app.id);
        var token = MakeToken(app.id, auth.id);
        await _store.CreateAsync(token, CancellationToken.None);

        var copy1 = (await _store.FindByIdAsync(token.id.ToString(), CancellationToken.None))!;
        var copy2 = (await _store.FindByIdAsync(token.id.ToString(), CancellationToken.None))!;

        copy1.Props.Status = OpenIddictConstants.Statuses.Revoked;
        await _store.UpdateAsync(copy1, CancellationToken.None);

        copy2.note = "stale";
        Func<Task> act = async () => await _store.UpdateAsync(copy2, CancellationToken.None);
        await act.Should().ThrowAsync<OpenIddictExceptions.ConcurrencyException>();
    }

    [Fact]
    public async Task GettersSetters_Roundtrip()
    {
        var app = await CreateTestAppAsync();
        var auth = await CreateTestAuthAsync(app.id);
        var token = await _store.InstantiateAsync(CancellationToken.None);
        var ct = CancellationToken.None;
        var subjectGuid = Guid.NewGuid();
        var subjectStr = subjectGuid.ToString("D");

        await _store.SetApplicationIdAsync(token, app.id.ToString(), ct);
        await _store.SetAuthorizationIdAsync(token, auth.id.ToString(), ct);
        await _store.SetSubjectAsync(token, subjectStr, ct);
        await _store.SetStatusAsync(token, OpenIddictConstants.Statuses.Valid, ct);
        await _store.SetTypeAsync(token, "access_token", ct);
        await _store.SetReferenceIdAsync(token, "my-ref", ct);
        await _store.SetPayloadAsync(token, "{}", ct);

        var now = DateTimeOffset.UtcNow;
        await _store.SetCreationDateAsync(token, now, ct);
        await _store.SetExpirationDateAsync(token, now.AddHours(1), ct);
        await _store.SetRedemptionDateAsync(token, now.AddMinutes(5), ct);

        (await _store.GetApplicationIdAsync(token, ct)).Should().Be(app.id.ToString());
        (await _store.GetAuthorizationIdAsync(token, ct)).Should().Be(auth.id.ToString());
        (await _store.GetSubjectAsync(token, ct)).Should().Be(subjectStr);
        (await _store.GetStatusAsync(token, ct)).Should().Be(OpenIddictConstants.Statuses.Valid);
        (await _store.GetTypeAsync(token, ct)).Should().Be("access_token");
        (await _store.GetReferenceIdAsync(token, ct)).Should().Be("my-ref");
        (await _store.GetPayloadAsync(token, ct)).Should().Be("{}");
        (await _store.GetCreationDateAsync(token, ct)).Should().BeCloseTo(now, TimeSpan.FromSeconds(1));
        (await _store.GetExpirationDateAsync(token, ct)).Should().BeCloseTo(now.AddHours(1), TimeSpan.FromSeconds(1));
        (await _store.GetRedemptionDateAsync(token, ct)).Should().BeCloseTo(now.AddMinutes(5), TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task CountAsync_IncludesCreatedEntities()
    {
        var before = await _store.CountAsync(CancellationToken.None);
        var app = await CreateTestAppAsync();
        var auth = await CreateTestAuthAsync(app.id);
        var token = MakeToken(app.id, auth.id);
        await _store.CreateAsync(token, CancellationToken.None);
        var after = await _store.CountAsync(CancellationToken.None);
        after.Should().BeGreaterThan(before);
    }

    [Fact]
    public async Task PruneAsync_DeletesNonValidTokens()
    {
        var ct = CancellationToken.None;
        var app = await CreateTestAppAsync();
        var auth = await CreateTestAuthAsync(app.id);

        var revoked = MakeToken(app.id, auth.id);
        revoked.Props.Status = OpenIddictConstants.Statuses.Revoked;
        await _store.CreateAsync(revoked, ct);

        // Threshold in the future ensures creation date is before threshold
        var threshold = DateTimeOffset.UtcNow.AddMinutes(1);
        var pruned = await _store.PruneAsync(threshold, ct);

        pruned.Should().BeGreaterOrEqualTo(1);
        (await _store.FindByIdAsync(revoked.id.ToString(), ct)).Should().BeNull();
    }

    [Fact]
    public async Task PruneAsync_DeletesTokensWithRevokedAuthorization()
    {
        var ct = CancellationToken.None;
        var app = await CreateTestAppAsync();
        var auth = await CreateTestAuthAsync(app.id);

        // Token is valid, but authorization will be revoked
        var token = MakeToken(app.id, auth.id);
        await _store.CreateAsync(token, ct);

        // Revoke the authorization
        await _authStore.SetStatusAsync(auth, OpenIddictConstants.Statuses.Revoked, ct);
        await _authStore.UpdateAsync(auth, ct);

        var threshold = DateTimeOffset.UtcNow.AddMinutes(1);
        var pruned = await _store.PruneAsync(threshold, ct);

        pruned.Should().BeGreaterOrEqualTo(1);
        (await _store.FindByIdAsync(token.id.ToString(), ct)).Should().BeNull();
    }

    [Fact]
    public async Task PruneAsync_DeletesTokensWithMissingAuthorization()
    {
        var ct = CancellationToken.None;
        var app = await CreateTestAppAsync();
        var auth = await CreateTestAuthAsync(app.id);
        var authId = auth.id;

        // Token references an authorization that will be deleted
        var token = MakeToken(app.id, authId);
        await _store.CreateAsync(token, ct);

        // Delete the authorization
        await _authStore.DeleteAsync(auth, ct);

        var threshold = DateTimeOffset.UtcNow.AddMinutes(1);
        var pruned = await _store.PruneAsync(threshold, ct);

        pruned.Should().BeGreaterOrEqualTo(1);
        (await _store.FindByIdAsync(token.id.ToString(), ct)).Should().BeNull();
    }

    [Fact]
    public async Task PruneAsync_KeepsValidTokensWithValidAuthorization()
    {
        var ct = CancellationToken.None;
        var app = await CreateTestAppAsync();
        var auth = await CreateTestAuthAsync(app.id); // Status = Valid

        var token = MakeToken(app.id, auth.id);
        await _store.CreateAsync(token, ct);

        var threshold = DateTimeOffset.UtcNow.AddMinutes(1);
        await _store.PruneAsync(threshold, ct);

        (await _store.FindByIdAsync(token.id.ToString(), ct)).Should().NotBeNull(
            "valid token with valid authorization should survive prune");
    }
}
