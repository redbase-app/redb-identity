using FluentAssertions;
using NSubstitute;
using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Users;
using redb.Identity.Contracts.Routes;
using redb.Identity.Http.Controllers;
using redb.Route.Abstractions;
using Xunit;

namespace redb.Identity.Tests.Http.Controllers;

public class UsersControllerTests
{
    private readonly IRouteContext _ctx = Substitute.For<IRouteContext>();
    private readonly IEndpoint _endpoint = Substitute.For<IEndpoint>();
    private readonly IProducer _producer = Substitute.For<IProducer>();
    private readonly UsersController _sut;

    private IExchange? _captured;

    public UsersControllerTests()
    {
        _ctx.GetEndpoint(IdentityEndpoints.ManageUsers).Returns(_endpoint);
        _endpoint.CreateProducer().Returns(_producer);
        _producer.Process(Arg.Do<IExchange>(e => _captured = e), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);

        _sut = new UsersController();
        _sut.Context = _ctx;
    }

    [Fact]
    public async Task Get_NumericId()
    {
        await _sut.Get("100");

        _captured!.In.Headers["operation"].Should().Be("read");
        var body = _captured.In.Body as Dictionary<string, object>;
        body!["id"].Should().Be(100L);
    }

    [Fact]
    public async Task Get_StringId_ForwardsAsLogin()
    {
        await _sut.Get("admin");

        _captured!.In.Headers["operation"].Should().Be("read");
        var body = _captured.In.Body as Dictionary<string, object>;
        body!["login"].Should().Be("admin");
    }

    [Fact]
    public async Task Update_SetsNumericId()
    {
        var req = new UpdateUserRequest { DisplayName = "John" };
        await _sut.Update("55", req);

        _captured!.In.Headers["operation"].Should().Be("update");
        req.Id.Should().Be(55L);
        _captured.In.Body.Should().BeSameAs(req);
    }

    [Fact]
    public async Task Update_NonNumericId_DoesNotSetId()
    {
        var req = new UpdateUserRequest { DisplayName = "John" };
        await _sut.Update("admin", req);

        _captured!.In.Headers["operation"].Should().Be("update");
        req.Id.Should().Be(0L);
    }

    [Fact]
    public async Task Delete_NumericId()
    {
        await _sut.Delete("10");

        _captured!.In.Headers["operation"].Should().Be("delete");
        var body = _captured.In.Body as Dictionary<string, object>;
        body!["id"].Should().Be(10L);
    }

    [Fact]
    public async Task ChangePassword_SetsNumericId()
    {
        var req = new ChangePasswordRequest { OldPassword = "old", NewPassword = "new" };
        await _sut.ChangePassword("77", req);

        _captured!.In.Headers["operation"].Should().Be("change-password");
        req.Id.Should().Be(77L);
    }
}
