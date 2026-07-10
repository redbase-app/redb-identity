using FluentAssertions;
using NSubstitute;
using redb.Identity.Contracts.Routes;
using redb.Identity.Http.Controllers;
using redb.Route.Abstractions;
using Xunit;

namespace redb.Identity.Tests.Http.Controllers;

public class TokensControllerTests
{
    private readonly IRouteContext _ctx = Substitute.For<IRouteContext>();
    private readonly IEndpoint _endpoint = Substitute.For<IEndpoint>();
    private readonly IProducer _producer = Substitute.For<IProducer>();
    private readonly TokensController _sut;

    private IExchange? _captured;

    public TokensControllerTests()
    {
        _ctx.GetEndpoint(IdentityEndpoints.ManageTokens).Returns(_endpoint);
        _endpoint.CreateProducer().Returns(_producer);
        _producer.Process(Arg.Do<IExchange>(e => _captured = e), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);

        _sut = new TokensController();
        _sut.Context = _ctx;
    }

    [Fact]
    public async Task List_WithGuidSubject()
    {
        var subject = Guid.NewGuid().ToString("D");
        await _sut.List(subject: subject, offset: 0, count: 10);

        var body = _captured!.In.Body as Dictionary<string, object?>;
        body!["subject"].Should().Be(subject,
            "subject is now a per-user GUID — controller forwards the raw string");
    }

    [Fact]
    public async Task List_WithStringSubject()
    {
        await _sut.List(subject: "admin");

        var body = _captured!.In.Body as Dictionary<string, object?>;
        body!["subject"].Should().Be("admin");
    }

    [Fact]
    public async Task Revoke_NumericId()
    {
        await _sut.Revoke("99");

        _captured!.In.Headers["operation"].Should().Be("revoke");
        var body = _captured.In.Body as Dictionary<string, object>;
        body!["tokenId"].Should().Be(99L);
    }

    [Fact]
    public async Task Revoke_StringId()
    {
        await _sut.Revoke("abc-token");

        _captured!.In.Headers["operation"].Should().Be("revoke");
        var body = _captured.In.Body as Dictionary<string, object>;
        body!["tokenId"].Should().Be("abc-token");
    }

    [Fact]
    public async Task RevokeBySubject_ForwardsRequestDict()
    {
        var request = new Dictionary<string, object>
        {
            ["subject"] = "user-123",
            ["type"] = "access_token"
        };

        await _sut.RevokeBySubject(request);

        _captured!.In.Headers["operation"].Should().Be("revoke-by-user");
        _captured.In.Body.Should().BeSameAs(request);
    }

    [Fact]
    public async Task Prune_ForwardsWithPruneOperation()
    {
        await _sut.Prune();

        _captured!.In.Headers["operation"].Should().Be("prune");
    }

    [Fact]
    public async Task Prune_SetsInOutPattern()
    {
        await _sut.Prune();

        _captured!.Pattern.Should().Be(ExchangePattern.InOut);
    }
}
