using FluentAssertions;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Session;

/// <summary>
/// A session remembers which relying parties obtained tokens through it
/// (<see cref="SessionProps.ClientApplicationIds"/>), because that list is who its back-channel logout
/// goes to. The binding is idempotent, keeps first-seen order, and refuses a revoked session.
/// </summary>
[Collection("Postgres")]
public sealed class SessionBindClientTests
{
    private readonly PostgresFixture _fx;

    public SessionBindClientTests(PostgresFixture fx) => _fx = fx;

    [Fact]
    public async Task Binding_is_idempotent_and_keeps_first_seen_order()
    {
        var sessions = new SessionService(_fx.Redb);
        var session = await sessions.CreateAsync(userId: 424242, applicationObjectId: 0);

        (await sessions.BindClientAsync(session.id, 10)).Should().BeTrue();
        (await sessions.BindClientAsync(session.id, 10)).Should().BeTrue("binding the same client again is a no-op, not an error");
        (await sessions.BindClientAsync(session.id, 11)).Should().BeTrue();

        var reloaded = await _fx.Redb.LoadAsync<SessionProps>(session.id);
        reloaded!.Props.ClientApplicationIds.Should().Equal(10L, 11L);
    }

    [Fact]
    public async Task A_revoked_session_takes_no_new_clients()
    {
        var sessions = new SessionService(_fx.Redb);
        var session = await sessions.CreateAsync(userId: 424243, applicationObjectId: 0);
        await sessions.RevokeAsync(session.id);

        (await sessions.BindClientAsync(session.id, 12)).Should().BeFalse();

        var reloaded = await _fx.Redb.LoadAsync<SessionProps>(session.id);
        reloaded!.Props.ClientApplicationIds.Should().BeNullOrEmpty();
    }

    [Fact]
    public async Task Nothing_is_bound_without_a_session_or_a_client()
    {
        var sessions = new SessionService(_fx.Redb);
        (await sessions.BindClientAsync(0, 10)).Should().BeFalse();
        (await sessions.BindClientAsync(1, 0)).Should().BeFalse();
    }
}
