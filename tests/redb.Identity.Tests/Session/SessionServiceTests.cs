using FluentAssertions;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.Session;

/// <summary>
/// Store-level tests for <see cref="SessionService"/>.
/// Uses <see cref="PostgresFixture"/> (raw redb + PostgreSQL, no OpenIddict pipeline).
/// </summary>
[Collection("Postgres")]
public class SessionServiceTests
{
    private readonly PostgresFixture _fx;
    private readonly ITestOutputHelper _output;

    public SessionServiceTests(PostgresFixture fx, ITestOutputHelper output)
    {
        _fx = fx;
        _output = output;
    }

    [Fact]
    public async Task Create_CreatesActiveSession()
    {
        var svc = new SessionService(_fx.Redb);
        var session = await svc.CreateAsync(userId: 1, applicationObjectId: 100);

        session.Should().NotBeNull();
        session.id.Should().BeGreaterThan(0);
        session.key.Should().Be(1);
        session.Props.Status.Should().Be("active");
        session.Props.ApplicationObjectId.Should().Be(100);

        _output.WriteLine($"Created session {session.id}");
    }

    [Fact]
    public async Task List_ReturnsActiveSessions()
    {
        var svc = new SessionService(_fx.Redb);

        // Create test app
        var app = await CreateTestApp("session-list-test");

        // Create sessions for a unique user
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        await svc.CreateAsync(userId, app.id);
        await svc.CreateAsync(userId, app.id);

        var sessions = await svc.ListAsync(userId);

        sessions.Should().HaveCountGreaterOrEqualTo(2);
        sessions.Should().OnlyContain(s => s.Status == "active");
        sessions.Should().OnlyContain(s => s.UserId == userId);

        _output.WriteLine($"Found {sessions.Count} sessions for user {userId}");
    }

    [Fact]
    public async Task List_IncludesApplicationInfo()
    {
        var svc = new SessionService(_fx.Redb);
        var app = await CreateTestApp("session-app-info-test");

        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        await svc.CreateAsync(userId, app.id);

        var sessions = await svc.ListAsync(userId);

        sessions.Should().Contain(s =>
            s.ApplicationObjectId == app.id &&
            s.ClientId == app.Props.ClientId);
    }

    [Fact]
    public async Task Revoke_RevokesSpecificSession()
    {
        var svc = new SessionService(_fx.Redb);
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        var session = await svc.CreateAsync(userId, 100);
        var revoked = await svc.RevokeAsync(session.id);

        revoked.Should().Be(1);

        // Verify it's not listed anymore
        var sessions = await svc.ListAsync(userId);
        sessions.Should().NotContain(s => s.SessionId == session.id);
    }

    [Fact]
    public async Task Revoke_AlreadyRevoked_ReturnsZero()
    {
        var svc = new SessionService(_fx.Redb);
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        var session = await svc.CreateAsync(userId, 100);
        await svc.RevokeAsync(session.id);

        var result = await svc.RevokeAsync(session.id);
        result.Should().Be(0);
    }

    [Fact]
    public async Task Revoke_NonExistent_ReturnsZero()
    {
        var svc = new SessionService(_fx.Redb);
        var result = await svc.RevokeAsync(999999999);
        result.Should().Be(0);
    }

    [Fact]
    public async Task RevokeAll_RevokesAllUserSessions()
    {
        var svc = new SessionService(_fx.Redb);
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        await svc.CreateAsync(userId, 100);
        await svc.CreateAsync(userId, 101);
        await svc.CreateAsync(userId, 102);

        var revoked = await svc.RevokeAllAsync(userId);
        revoked.Should().Be(3);

        var remaining = await svc.ListAsync(userId);
        remaining.Should().BeEmpty();
    }

    [Fact]
    public async Task RevokeAll_DoesNotAffectOtherUsers()
    {
        var svc = new SessionService(_fx.Redb);
        var user1 = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var user2 = user1 + 1;

        await svc.CreateAsync(user1, 100);
        await svc.CreateAsync(user2, 100);

        await svc.RevokeAllAsync(user1);

        var user2Sessions = await svc.ListAsync(user2);
        user2Sessions.Should().HaveCountGreaterOrEqualTo(1);
    }

    [Fact]
    public async Task Logout_RevokesSessionsAndAuthorizations()
    {
        var svc = new SessionService(_fx.Redb);
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var app = await CreateTestApp("session-logout-test");

        // Create session
        await svc.CreateAsync(userId, app.id);

        // Create authorization for the same user
        var auth = new redb.Core.Models.Entities.RedbObject<AuthorizationProps>
        {
            key = userId,
            Props = new AuthorizationProps
            {
                ApplicationObjectId = app.id,
                Status = "valid",
                Type = "permanent"
            }
        };
        auth.id = await _fx.Redb.SaveAsync(auth);

        // Perform logout
        var sessionsRevoked = await svc.LogoutAsync(userId);
        sessionsRevoked.Should().BeGreaterOrEqualTo(1);

        // Verify sessions are revoked
        var sessions = await svc.ListAsync(userId);
        sessions.Should().BeEmpty();

        // Verify authorization is revoked
        var reloadedAuth = await _fx.Redb.LoadAsync<AuthorizationProps>(auth.id);
        reloadedAuth!.Props.Status.Should().Be("revoked");
    }

    [Fact]
    public async Task List_DoesNotReturnRevokedSessions()
    {
        var svc = new SessionService(_fx.Redb);
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        await svc.CreateAsync(userId, 100);
        var toRevoke = await svc.CreateAsync(userId, 101);
        await svc.RevokeAsync(toRevoke.id);

        var sessions = await svc.ListAsync(userId);
        sessions.Should().HaveCount(1);
        sessions[0].ApplicationObjectId.Should().Be(100);
    }

    private async Task<redb.Core.Models.Entities.RedbObject<ApplicationProps>> CreateTestApp(string suffix)
    {
        var app = new redb.Core.Models.Entities.RedbObject<ApplicationProps>
        {
            Name = $"SessionTest-{suffix}-{DateTimeOffset.UtcNow.Ticks}",
            Props = new ApplicationProps
            {
                ClientId = $"session-test-{suffix}-{DateTimeOffset.UtcNow.Ticks}",
                ClientType = "public"
            }
        };
        app.value_string = app.Props.ClientId;
        app.id = await _fx.Redb.SaveAsync(app);
        return app;
    }
}
