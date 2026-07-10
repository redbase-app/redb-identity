using FluentAssertions;
using NSubstitute;
using redb.Identity.Contracts.Applications;
using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Routes;
using redb.Identity.Http.Controllers;
using redb.Route.Abstractions;
using Xunit;

namespace redb.Identity.Tests.Http.Controllers;

public class ApplicationsControllerTests
{
    private readonly IRouteContext _ctx = Substitute.For<IRouteContext>();
    private readonly IEndpoint _endpoint = Substitute.For<IEndpoint>();
    private readonly IProducer _producer = Substitute.For<IProducer>();
    private readonly ApplicationsController _sut;

    private IExchange? _captured;

    public ApplicationsControllerTests()
    {
        _ctx.GetEndpoint(IdentityEndpoints.ManageApps).Returns(_endpoint);
        _endpoint.CreateProducer().Returns(_producer);
        _producer.Process(Arg.Do<IExchange>(e => _captured = e), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);

        _sut = new ApplicationsController();
        _sut.Context = _ctx;
    }

    [Fact]
    public async Task Get_NumericId_ForwardsWithNumericId()
    {
        await _sut.Get("42");

        _captured!.In.Headers["operation"].Should().Be("read");
        var body = _captured.In.Body as Dictionary<string, object>;
        body.Should().NotBeNull();
        body!["id"].Should().Be(42L);
    }

    [Fact]
    public async Task Get_StringId_ForwardsWithClientId()
    {
        await _sut.Get("my-app");

        _captured!.In.Headers["operation"].Should().Be("read");
        var body = _captured.In.Body as Dictionary<string, object>;
        body.Should().NotBeNull();
        body!["clientId"].Should().Be("my-app");
    }

    [Fact]
    public async Task Update_SetsIdOnRequest()
    {
        var req = new UpdateApplicationRequest { DisplayName = "Updated" };
        await _sut.Update("app-1", req);

        _captured!.In.Headers["operation"].Should().Be("update");
        req.Id.Should().Be("app-1");
        _captured.In.Body.Should().BeSameAs(req);
    }

    [Fact]
    public async Task Delete_NumericId_ForwardsWithNumericId()
    {
        await _sut.Delete("99");

        _captured!.In.Headers["operation"].Should().Be("delete");
        var body = _captured.In.Body as Dictionary<string, object>;
        body!["id"].Should().Be(99L);
    }

    [Fact]
    public async Task Delete_StringId_ForwardsWithClientId()
    {
        await _sut.Delete("my-app");

        _captured!.In.Headers["operation"].Should().Be("delete");
        var body = _captured.In.Body as Dictionary<string, object>;
        body!["clientId"].Should().Be("my-app");
    }

    [Fact]
    public async Task Forward_SetsInOutPattern()
    {
        await _sut.List();

        _captured!.Pattern.Should().Be(ExchangePattern.InOut);
    }

    [Fact]
    public async Task Forward_ReturnsOutBody_WhenAvailable()
    {
        _producer.Process(Arg.Any<IExchange>(), Arg.Any<CancellationToken>())
            .Returns(ci =>
            {
                var ex = ci.Arg<IExchange>();
                // Simulate pipeline setting Out
                ex.Out = Substitute.For<IMessage>();
                ex.Out.Body.Returns("result-data");
                return Task.CompletedTask;
            });

        var result = await _sut.List();

        result.Should().Be("result-data");
    }
}
