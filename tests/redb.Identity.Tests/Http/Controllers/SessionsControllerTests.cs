using FluentAssertions;
using NSubstitute;
using redb.Identity.Contracts.Routes;
using redb.Identity.Http.Controllers;
using redb.Route.Abstractions;
using Xunit;

namespace redb.Identity.Tests.Http.Controllers;

public class SessionsControllerTests
{
    private readonly IRouteContext _ctx = Substitute.For<IRouteContext>();
    private readonly IEndpoint _endpoint = Substitute.For<IEndpoint>();
    private readonly IProducer _producer = Substitute.For<IProducer>();
    private readonly SessionsController _sut;

    private IExchange? _captured;

    public SessionsControllerTests()
    {
        _ctx.GetEndpoint(IdentityEndpoints.ManageSessions).Returns(_endpoint);
        _endpoint.CreateProducer().Returns(_producer);
        _producer.Process(Arg.Do<IExchange>(e => _captured = e), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);

        _sut = new SessionsController();
        _sut.Context = _ctx;
    }

    // ── List ──
    //
    // SessionsController.List dispatches on whether userId was supplied —
    // null/empty routes to the new "list-all" admin-wide browse, a
    // value routes to the targeted per-user "list".

    [Fact]
    public async Task List_NumericUserId_ForwardsAsLongAndPicksListOp()
    {
        await _sut.List(userId: "42");

        _captured!.In.Headers["operation"].Should().Be("list");
        var body = _captured.In.Body as Dictionary<string, object?>;
        body.Should().NotBeNull();
        body!["userId"].Should().Be(42L);
    }

    [Fact]
    public async Task List_NonNumericUserId_DefaultsToZero()
    {
        await _sut.List(userId: "abc");

        _captured!.In.Headers["operation"].Should().Be("list");
        var body = _captured.In.Body as Dictionary<string, object?>;
        body!["userId"].Should().Be(0L);
    }

    [Fact]
    public async Task List_NoUserId_RoutesToListAllWithPagination()
    {
        await _sut.List(userId: null, offset: "50", count: "100");

        _captured!.In.Headers["operation"].Should().Be("list-all");
        var body = _captured.In.Body as Dictionary<string, object?>;
        body.Should().NotBeNull();
        body!["offset"].Should().Be(50L);
        body!["count"].Should().Be(100L);
    }

    [Fact]
    public async Task List_NoUserId_DefaultsPagination()
    {
        await _sut.List(userId: null);

        _captured!.In.Headers["operation"].Should().Be("list-all");
        var body = _captured.In.Body as Dictionary<string, object?>;
        body!["offset"].Should().Be(0L);
        body!["count"].Should().Be(25L);
    }

    // ── Revoke ──

    [Fact]
    public async Task Revoke_NumericId_ForwardsSessionId()
    {
        await _sut.Revoke("99");

        _captured!.In.Headers["operation"].Should().Be("revoke");
        var body = _captured.In.Body as Dictionary<string, object?>;
        body!["sessionId"].Should().Be(99L);
    }

    [Fact]
    public async Task Revoke_NonNumericId_DefaultsToZero()
    {
        await _sut.Revoke("not-a-number");

        var body = _captured!.In.Body as Dictionary<string, object?>;
        body!["sessionId"].Should().Be(0L);
    }

    // ── RevokeAll ──

    [Fact]
    public async Task RevokeAll_NumericId_ForwardsUserId()
    {
        await _sut.RevokeAll("7");

        _captured!.In.Headers["operation"].Should().Be("revoke-all");
        var body = _captured.In.Body as Dictionary<string, object?>;
        body!["userId"].Should().Be(7L);
    }

    // ── Logout ──

    [Fact]
    public async Task Logout_NumericId_ForwardsUserId()
    {
        await _sut.Logout("100");

        _captured!.In.Headers["operation"].Should().Be("logout");
        var body = _captured.In.Body as Dictionary<string, object?>;
        body!["userId"].Should().Be(100L);
    }

    [Fact]
    public async Task Logout_NonNumericId_DefaultsToZero()
    {
        await _sut.Logout("xyz");

        _captured!.In.Headers["operation"].Should().Be("logout");
        var body = _captured.In.Body as Dictionary<string, object?>;
        body!["userId"].Should().Be(0L);
    }

    // ── Exchange pattern ──

    [Fact]
    public async Task Forward_SetsInOutPattern()
    {
        await _sut.List(userId: "1");

        _captured!.Pattern.Should().Be(ExchangePattern.InOut);
    }
}
