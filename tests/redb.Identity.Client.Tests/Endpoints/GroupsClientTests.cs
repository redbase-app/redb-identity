using System.Net;
using FluentAssertions;
using redb.Identity.Client.Tests.TestKit;
using redb.Identity.Contracts.Groups;
using Xunit;

namespace redb.Identity.Client.Tests.Endpoints;

public sealed class GroupsClientTests
{
    [Fact]
    public async Task ListRootGroups_GETs_paged()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "[{\"id\":1,\"name\":\"root\"}]");
        var result = await fx.Client.ListRootGroupsAsync(0, 25);
        fx.Handler.Requests.Single().RequestUri!.PathAndQuery.Should().Be("/api/v1/identity/groups?offset=0&count=25");
        result[0].Name.Should().Be("root");
    }

    [Fact]
    public async Task GetGroup_GET_by_id()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(new GroupResponse { Id = 7, Name = "g" }));
        var g = await fx.Client.GetGroupAsync(7);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/groups/7");
        g.Id.Should().Be(7);
    }

    [Fact]
    public async Task CreateGroup_POST()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.Created, IdentityClientFixture.Json(new GroupResponse { Id = 1, Name = "g" }));
        await fx.Client.CreateGroupAsync(new CreateGroupRequest { Name = "g" });
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/groups");
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Post);
    }

    [Fact]
    public async Task CreateChildGroup_POST_to_children_subroute()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.Created, IdentityClientFixture.Json(new GroupResponse { Id = 2, Name = "c", ParentId = 1 }));
        await fx.Client.CreateChildGroupAsync(1, new CreateGroupRequest { Name = "c" });
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/groups/1/children");
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Post);
    }

    [Fact]
    public async Task UpdateGroup_PUT()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"success\":true,\"groupId\":1}");
        await fx.Client.UpdateGroupAsync(1, new UpdateGroupRequest { Name = "renamed" });
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Put);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/groups/1");
    }

    [Fact]
    public async Task DeleteGroup_DELETE()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"success\":true}");
        await fx.Client.DeleteGroupAsync(1);
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Delete);
    }

    [Fact]
    public async Task MoveGroup_POSTs_move_subroute()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"success\":true}");
        await fx.Client.MoveGroupAsync(1, new MoveGroupRequest { NewParentGroupId = 2 });
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/groups/1/move");
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Post);
    }

    [Fact]
    public async Task GetGroupTree_GETs_tree_subroute_returns_JsonElement()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"id\":1,\"name\":\"r\",\"children\":[]}");
        var tree = await fx.Client.GetGroupTreeAsync(1);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/groups/1/tree");
        tree.GetProperty("name").GetString().Should().Be("r");
    }

    [Fact]
    public async Task GetGroupPath_GETs_path()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "[{\"id\":1,\"name\":\"r\"}]");
        var path = await fx.Client.GetGroupPathAsync(1);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/groups/1/path");
        path.Should().ContainSingle();
    }

    [Fact]
    public async Task GetGroupChildren_GETs_children()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "[{\"id\":2,\"name\":\"c\"}]");
        var ch = await fx.Client.GetGroupChildrenAsync(1);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/groups/1/children");
        ch.Should().ContainSingle();
    }

    [Fact]
    public async Task ListGroupMembers_GETs_members()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(new[] { new MemberResponse { MembershipId = 10, UserId = 5, GroupId = 1, Role = "member" } }));
        var members = await fx.Client.ListGroupMembersAsync(1);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/groups/1/members");
        members.Should().ContainSingle().Which.UserId.Should().Be(5);
    }

    [Fact]
    public async Task AddGroupMember_POSTs_to_members_subroute()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"success\":true}");
        await fx.Client.AddGroupMemberAsync(1, new AddMemberRequest { UserId = 5, Role = "admin" });
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/groups/1/members");
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Post);
    }

    [Fact]
    public async Task UpdateGroupMember_PUT_to_user_subroute()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"success\":true}");
        await fx.Client.UpdateGroupMemberAsync(1, 5, new UpdateMemberRequest { Role = "owner" });
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/groups/1/members/5");
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Put);
    }

    [Fact]
    public async Task RemoveGroupMember_DELETEs_user_subroute()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"success\":true}");
        await fx.Client.RemoveGroupMemberAsync(1, 5);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/groups/1/members/5");
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Delete);
    }

    [Fact]
    public async Task GetUserGroups_GETs_users_subroute()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "[{\"groupId\":1,\"groupName\":\"g\",\"role\":\"member\"}]");
        var ug = await fx.Client.GetUserGroupsAsync(5);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/groups/users/5/groups");
        ug.GetArrayLength().Should().Be(1);
    }

    [Fact]
    public async Task IsGroupMember_GETs_check_subroute_returns_bool()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"isMember\":true,\"groupId\":1,\"userId\":5}");
        var ok = await fx.Client.IsGroupMemberAsync(1, 5);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/groups/1/members/5/check");
        ok.Should().BeTrue();
    }
}
