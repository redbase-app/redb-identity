using FluentAssertions;
using OpenIddict.Abstractions;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Consent;

[Collection("Postgres")]
public class ConsentServiceTests
{
    private readonly ConsentService _consent;
    private readonly PostgresFixture _fixture;

    public ConsentServiceTests(PostgresFixture fixture)
    {
        _fixture = fixture;
        _consent = new ConsentService(fixture.Redb);
    }

    private async Task<RedbObject<ApplicationProps>> CreateTestAppAsync(string? consentType = null)
    {
        var app = new RedbObject<ApplicationProps>
        {
            name = $"consent-test-app-{Guid.NewGuid():N}",
            Props = new ApplicationProps
            {
                ClientId = $"consent-app-{Guid.NewGuid():N}",
                ClientType = "confidential",
                ConsentType = consentType ?? "explicit"
            }
        };
        app.value_string = app.Props.ClientId;
        app.id = await _fixture.Redb.SaveAsync(app);
        return app;
    }

    private async Task<long> CreateTestUserAsync()
    {
        var login = $"consent-user-{Guid.NewGuid():N}";
        var coreUser = await _fixture.Redb.UserProvider.CreateUserAsync(
            new redb.Core.Models.Users.CreateUserRequest
            {
                Login = login,
                Password = "Test1234!",
                Name = login,
                Enabled = true
            });
        return coreUser.Id;
    }

    [Fact]
    public async Task CheckAsync_NoConsent_ReturnsNull()
    {
        var app = await CreateTestAppAsync();
        var userId = await CreateTestUserAsync();

        var result = await _consent.CheckAsync(userId, app.id, ["openid", "profile"]);

        result.Should().BeNull();
    }

    [Fact]
    public async Task GrantAsync_CreatesNewConsent()
    {
        var app = await CreateTestAppAsync();
        var userId = await CreateTestUserAsync();

        var consent = await _consent.GrantAsync(userId, app.id, ["openid", "profile"]);

        consent.Should().NotBeNull();
        consent.id.Should().BeGreaterThan(0);
        consent.Props.Status.Should().Be(OpenIddictConstants.Statuses.Valid);
        consent.Props.Type.Should().Be(OpenIddictConstants.AuthorizationTypes.Permanent);
        consent.Props.Scopes.Should().BeEquivalentTo(["openid", "profile"]);
        consent.key.Should().Be(userId);
        consent.Props.ApplicationObjectId.Should().Be(app.id);
    }

    [Fact]
    public async Task CheckAsync_AfterGrant_ReturnsConsent()
    {
        var app = await CreateTestAppAsync();
        var userId = await CreateTestUserAsync();

        await _consent.GrantAsync(userId, app.id, ["openid", "profile", "email"]);

        // Check with subset of scopes — should match
        var result = await _consent.CheckAsync(userId, app.id, ["openid", "profile"]);

        result.Should().NotBeNull();
        result!.Props.Scopes.Should().Contain("openid");
        result.Props.Scopes.Should().Contain("profile");
        result.Props.Scopes.Should().Contain("email");
    }

    [Fact]
    public async Task CheckAsync_InsufficientScopes_ReturnsNull()
    {
        var app = await CreateTestAppAsync();
        var userId = await CreateTestUserAsync();

        await _consent.GrantAsync(userId, app.id, ["openid"]);

        // Require more scopes than granted
        var result = await _consent.CheckAsync(userId, app.id, ["openid", "profile"]);

        result.Should().BeNull();
    }

    [Fact]
    public async Task GrantAsync_ExistingConsent_MergesScopes()
    {
        var app = await CreateTestAppAsync();
        var userId = await CreateTestUserAsync();

        var first = await _consent.GrantAsync(userId, app.id, ["openid", "profile"]);
        var second = await _consent.GrantAsync(userId, app.id, ["openid", "email"]);

        // Should be the same record (merged), not a new one
        second.id.Should().Be(first.id);
        second.Props.Scopes.Should().BeEquivalentTo(["openid", "profile", "email"]);
    }

    [Fact]
    public async Task RevokeAsync_RevokesConsent()
    {
        var app = await CreateTestAppAsync();
        var userId = await CreateTestUserAsync();

        await _consent.GrantAsync(userId, app.id, ["openid", "profile"]);

        var revoked = await _consent.RevokeAsync(userId, app.id);

        revoked.Should().Be(1);

        // Check should return null after revocation
        var result = await _consent.CheckAsync(userId, app.id, ["openid"]);
        result.Should().BeNull();
    }

    [Fact]
    public async Task RevokeAsync_NoConsent_ReturnsZero()
    {
        var app = await CreateTestAppAsync();
        var userId = await CreateTestUserAsync();

        var revoked = await _consent.RevokeAsync(userId, app.id);

        revoked.Should().Be(0);
    }

    [Fact]
    public async Task RevokeAllAsync_RevokesAllConsents()
    {
        var app1 = await CreateTestAppAsync();
        var app2 = await CreateTestAppAsync();
        var userId = await CreateTestUserAsync();

        await _consent.GrantAsync(userId, app1.id, ["openid"]);
        await _consent.GrantAsync(userId, app2.id, ["openid", "profile"]);

        var revoked = await _consent.RevokeAllAsync(userId);

        revoked.Should().Be(2);

        var result1 = await _consent.CheckAsync(userId, app1.id, ["openid"]);
        var result2 = await _consent.CheckAsync(userId, app2.id, ["openid"]);
        result1.Should().BeNull();
        result2.Should().BeNull();
    }

    [Fact]
    public async Task ListAsync_ReturnsActiveConsents()
    {
        var app = await CreateTestAppAsync();
        var userId = await CreateTestUserAsync();

        await _consent.GrantAsync(userId, app.id, ["openid", "profile"]);

        var list = await _consent.ListAsync(userId);

        list.Should().ContainSingle(c => c.ApplicationId == app.id);
        var consent = list.First(c => c.ApplicationId == app.id);
        consent.ClientId.Should().Be(app.Props.ClientId);
        consent.Scopes.Should().BeEquivalentTo(["openid", "profile"]);
        consent.UserId.Should().Be(userId);
    }

    [Fact]
    public async Task ListAsync_ExcludesRevokedConsents()
    {
        var app = await CreateTestAppAsync();
        var userId = await CreateTestUserAsync();

        await _consent.GrantAsync(userId, app.id, ["openid"]);
        await _consent.RevokeAsync(userId, app.id);

        var list = await _consent.ListAsync(userId);

        list.Should().NotContain(c => c.ApplicationId == app.id);
    }

    [Fact]
    public async Task FindApplicationIdAsync_ReturnsAppId()
    {
        var app = await CreateTestAppAsync();

        var result = await _consent.FindApplicationIdAsync(app.Props.ClientId!);

        result.Should().Be(app.id);
    }

    [Fact]
    public async Task FindApplicationIdAsync_UnknownClient_ReturnsNull()
    {
        var result = await _consent.FindApplicationIdAsync("nonexistent-client-id");

        result.Should().BeNull();
    }
}
