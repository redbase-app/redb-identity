using FluentAssertions;
using NSubstitute;
using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Scopes;
using redb.Identity.Contracts.Routes;
using redb.Identity.Http.Controllers;
using redb.Route.Abstractions;
using Xunit;

namespace redb.Identity.Tests.Http.Controllers;

public class ScopesControllerTests
{
    private readonly IRouteContext _ctx = Substitute.For<IRouteContext>();
    private readonly IEndpoint _endpoint = Substitute.For<IEndpoint>();
    private readonly IProducer _producer = Substitute.For<IProducer>();
    private readonly ScopesController _sut;

    private IExchange? _captured;

    public ScopesControllerTests()
    {
        _ctx.GetEndpoint(IdentityEndpoints.ManageScopes).Returns(_endpoint);
        _endpoint.CreateProducer().Returns(_producer);
        _producer.Process(Arg.Do<IExchange>(e => _captured = e), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);

        _sut = new ScopesController();
        _sut.Context = _ctx;
    }

    [Fact]
    public async Task Get_NumericId_ForwardsNumeric()
    {
        await _sut.Get("7");

        _captured!.In.Headers["operation"].Should().Be("read");
        var body = _captured.In.Body as Dictionary<string, object>;
        body!["id"].Should().Be(7L);
    }

    [Fact]
    public async Task Get_StringId_ForwardsAsName()
    {
        await _sut.Get("openid");

        _captured!.In.Headers["operation"].Should().Be("read");
        var body = _captured.In.Body as Dictionary<string, object>;
        body!["name"].Should().Be("openid");
    }

    [Fact]
    public async Task Update_SetsIdOnRequest()
    {
        var req = new UpdateScopeRequest { DisplayName = "API Scope" };
        await _sut.Update("scope-1", req);

        _captured!.In.Headers["operation"].Should().Be("update");
        req.Id.Should().Be("scope-1");
        _captured.In.Body.Should().BeSameAs(req);
    }

    [Fact]
    public async Task Delete_NumericId()
    {
        await _sut.Delete("15");

        _captured!.In.Headers["operation"].Should().Be("delete");
        var body = _captured.In.Body as Dictionary<string, object>;
        body!["id"].Should().Be(15L);
    }

    [Fact]
    public async Task Delete_StringId_ForwardsAsName()
    {
        await _sut.Delete("profile");

        _captured!.In.Headers["operation"].Should().Be("delete");
        var body = _captured.In.Body as Dictionary<string, object>;
        body!["name"].Should().Be("profile");
    }
}
