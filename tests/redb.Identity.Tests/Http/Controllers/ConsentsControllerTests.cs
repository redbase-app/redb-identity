using FluentAssertions;
using NSubstitute;
using redb.Identity.Contracts.Routes;
using redb.Identity.Http.Controllers;
using redb.Route.Abstractions;
using Xunit;

namespace redb.Identity.Tests.Http.Controllers;

public class ConsentsControllerTests
{
    private readonly IRouteContext _ctx = Substitute.For<IRouteContext>();
    private readonly IEndpoint _endpoint = Substitute.For<IEndpoint>();
    private readonly IProducer _producer = Substitute.For<IProducer>();
    private readonly ConsentsController _sut;

    private IExchange? _captured;

    public ConsentsControllerTests()
    {
        _ctx.GetEndpoint(IdentityEndpoints.ManageConsents).Returns(_endpoint);
        _endpoint.CreateProducer().Returns(_producer);
        _producer.Process(Arg.Do<IExchange>(e => _captured = e), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);

        _sut = new ConsentsController();
        _sut.Context = _ctx;
    }

    // ── ListByUser ──

    [Fact]
    public async Task ListByUser_NumericId_ForwardsAsLong()
    {
        await _sut.ListByUser("42");

        _captured!.In.Headers["operation"].Should().Be("list");
        var body = _captured.In.Body as Dictionary<string, object?>;
        body.Should().NotBeNull();
        body!["userId"].Should().Be(42L);
    }

    [Fact]
    public async Task ListByUser_NonNumericId_DefaultsToZero()
    {
        await _sut.ListByUser("abc");

        var body = _captured!.In.Body as Dictionary<string, object?>;
        body!["userId"].Should().Be(0L);
    }

    // ── Revoke ──

    [Fact]
    public async Task Revoke_NumericIds_ForwardsUserAndAppId()
    {
        await _sut.Revoke("42", "99");

        _captured!.In.Headers["operation"].Should().Be("revoke");
        var body = _captured.In.Body as Dictionary<string, object?>;
        body.Should().NotBeNull();
        body!["userId"].Should().Be(42L);
        body["applicationId"].Should().Be(99L);
    }

    [Fact]
    public async Task Revoke_NonNumericUserId_DefaultsToZero()
    {
        await _sut.Revoke("abc", "99");

        var body = _captured!.In.Body as Dictionary<string, object?>;
        body!["userId"].Should().Be(0L);
        body["applicationId"].Should().Be(99L);
    }

    [Fact]
    public async Task Revoke_NonNumericAppId_DefaultsToZero()
    {
        await _sut.Revoke("42", "not-a-number");

        var body = _captured!.In.Body as Dictionary<string, object?>;
        body!["userId"].Should().Be(42L);
        body["applicationId"].Should().Be(0L);
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

    [Fact]
    public async Task RevokeAll_NonNumericId_DefaultsToZero()
    {
        await _sut.RevokeAll("xyz");

        var body = _captured!.In.Body as Dictionary<string, object?>;
        body!["userId"].Should().Be(0L);
    }

    // ── Exchange pattern ──

    [Fact]
    public async Task Forward_SetsInOutPattern()
    {
        await _sut.ListByUser("1");

        _captured!.Pattern.Should().Be(ExchangePattern.InOut);
    }
}
