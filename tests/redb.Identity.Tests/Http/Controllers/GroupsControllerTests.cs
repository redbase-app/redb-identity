using FluentAssertions;
using NSubstitute;
using redb.Identity.Contracts.Groups;
using redb.Identity.Contracts.Routes;
using redb.Identity.Http.Controllers;
using redb.Route.Abstractions;
using Xunit;

namespace redb.Identity.Tests.Http.Controllers;

public class GroupsControllerTests
{
    private readonly IRouteContext _ctx = Substitute.For<IRouteContext>();
    private readonly IEndpoint _endpoint = Substitute.For<IEndpoint>();
    private readonly IProducer _producer = Substitute.For<IProducer>();
    private readonly GroupsController _sut;

    private IExchange? _captured;

    public GroupsControllerTests()
    {
        _ctx.GetEndpoint(IdentityEndpoints.ManageGroups).Returns(_endpoint);
        _endpoint.CreateProducer().Returns(_producer);
        _producer.Process(Arg.Do<IExchange>(e => _captured = e), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);

        _sut = new GroupsController();
        _sut.Context = _ctx;
    }

    [Fact]
    public async Task Get_NumericId()
    {
        await _sut.Get("5");

        _captured!.In.Headers["operation"].Should().Be("read");
        var body = _captured.In.Body as Dictionary<string, object>;
        body!["groupId"].Should().Be(5L);
    }

    [Fact]
    public async Task Get_StringId()
    {
        await _sut.Get("admins");

        _captured!.In.Headers["operation"].Should().Be("read");
        var body = _captured.In.Body as Dictionary<string, object>;
        body!["groupId"].Should().Be("admins");
    }

    [Fact]
    public async Task Update_ForwardsIdAndBody()
    {
        var req = new UpdateGroupRequest { Name = "updated" };
        await _sut.Update("42", req);

        _captured!.In.Headers["operation"].Should().Be("update");
        var body = _captured.In.Body as Dictionary<string, object?>;
        body!["groupId"].Should().Be(42L);
        body["name"].Should().Be("updated");
    }

    [Fact]
    public async Task Delete_NumericId()
    {
        await _sut.Delete("10");

        _captured!.In.Headers["operation"].Should().Be("delete");
        var body = _captured.In.Body as Dictionary<string, object>;
        body!["groupId"].Should().Be(10L);
    }

    [Fact]
    public async Task AddMember_ForwardsGroupIdAndBody()
    {
        var req = new AddMemberRequest { UserId = 5L };
        await _sut.AddMember("42", req);

        _captured!.In.Headers["operation"].Should().Be("add-member");
        var body = _captured.In.Body as Dictionary<string, object?>;
        body!["groupId"].Should().Be(42L);
        body["userId"].Should().Be(5L);
    }

    [Fact]
    public async Task RemoveMember_ForwardsIds()
    {
        await _sut.RemoveMember("42", "5");

        _captured!.In.Headers["operation"].Should().Be("remove-member");
        var body = _captured.In.Body as Dictionary<string, object?>;
        body!["groupId"].Should().Be(42L);
        body["userId"].Should().Be(5L);
    }

    [Fact]
    public async Task CreateChild_ForwardsParentId()
    {
        var req = new CreateGroupRequest { Name = "ChildTeam", GroupType = "team" };
        await _sut.CreateChild("42", req);

        _captured!.In.Headers["operation"].Should().Be("create-child");
        var body = _captured.In.Body as Dictionary<string, object?>;
        body!["parentGroupId"].Should().Be(42L);
        body["name"].Should().Be("ChildTeam");
    }

    [Fact]
    public async Task Move_ForwardsGroupId()
    {
        var req = new MoveGroupRequest { NewParentGroupId = 99L };
        await _sut.Move("42", req);

        _captured!.In.Headers["operation"].Should().Be("move");
        var body = _captured.In.Body as Dictionary<string, object?>;
        body!["groupId"].Should().Be(42L);
        body["newParentGroupId"].Should().Be(99L);
    }

    [Fact]
    public async Task Tree_ForwardsGroupId()
    {
        await _sut.Tree("42");

        _captured!.In.Headers["operation"].Should().Be("tree");
        var body = _captured.In.Body as Dictionary<string, object>;
        body!["groupId"].Should().Be(42L);
    }

    [Fact]
    public async Task ListMembers_ForwardsGroupId()
    {
        await _sut.ListMembers("42");

        _captured!.In.Headers["operation"].Should().Be("list-members");
        var body = _captured.In.Body as Dictionary<string, object>;
        body!["groupId"].Should().Be(42L);
    }

    [Fact]
    public async Task UserGroups_ForwardsUserId()
    {
        await _sut.UserGroups("5");

        _captured!.In.Headers["operation"].Should().Be("user-groups");
        var body = _captured.In.Body as Dictionary<string, object?>;
        body!["userId"].Should().Be(5L);
    }

    [Fact]
    public async Task IsMember_ForwardsIds()
    {
        await _sut.IsMember("42", "5");

        _captured!.In.Headers["operation"].Should().Be("is-member");
        var body = _captured.In.Body as Dictionary<string, object?>;
        body!["groupId"].Should().Be(42L);
        body["userId"].Should().Be(5L);
    }
}
