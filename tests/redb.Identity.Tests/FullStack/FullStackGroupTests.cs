using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// Full-stack E2E tests for Group Management REST API.
/// Complete path: HTTP request → Kestrel → bearer auth → GroupsController
/// → direct-vm://identity-manage-groups → GroupManagementProcessor → GroupService
/// → redb PROPS → PostgreSQL → response → HTTP.
/// </summary>
[Collection("ProductionHttp")]
public class FullStackGroupTests
{
    private readonly ProductionHttpFixture _fx;
    private readonly HttpClient _http;
    private readonly ITestOutputHelper _output;

    public FullStackGroupTests(ProductionHttpFixture fx, ITestOutputHelper output)
    {
        _fx = fx;
        _http = fx.Http;
        _output = output;
    }

    private HttpRequestMessage WithAuth(HttpRequestMessage request)
    {
        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", _fx.ManagementToken);
        return request;
    }

    // ══════════════════════════════════════════════
    //  Auth guardrails
    // ══════════════════════════════════════════════

    [Fact]
    public async Task Groups_WithoutBearer_Returns401()
    {
        var resp = await _http.GetAsync("/api/v1/identity/groups");
        resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task GroupMembers_WithoutBearer_Returns401()
    {
        var resp = await _http.GetAsync("/api/v1/identity/groups/1/members");
        resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    // ══════════════════════════════════════════════
    //  Group CRUD — full lifecycle
    // ══════════════════════════════════════════════

    [Fact]
    public async Task Groups_CreateReadUpdateDelete_FullCycle()
    {
        // CREATE
        var createResp = await SendJson(HttpMethod.Post, "/api/v1/identity/groups",
            new { name = "HttpOrg1", groupType = "organization", description = "E2E org" });
        createResp.StatusCode.Should().Be(HttpStatusCode.OK,
            "create failed: {0}", await createResp.Content.ReadAsStringAsync());
        var created = await ParseJson(createResp);
        var id = created.GetProperty("id").GetInt64();
        id.Should().BeGreaterThan(0);
        created.GetProperty("name").GetString().Should().Be("HttpOrg1");
        created.GetProperty("groupType").GetString().Should().Be("organization");

        _output.WriteLine($"Created group {id}");

        // READ
        var readResp = await SendAuth(HttpMethod.Get, $"/api/v1/identity/groups/{id}");
        readResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var read = await ParseJson(readResp);
        read.GetProperty("id").GetInt64().Should().Be(id);
        read.GetProperty("description").GetString().Should().Be("E2E org");

        // UPDATE
        var updateResp = await SendJson(HttpMethod.Put, $"/api/v1/identity/groups/{id}",
            new { name = "HttpOrg1Updated", description = "Updated desc" });
        updateResp.StatusCode.Should().Be(HttpStatusCode.OK);

        // Verify update via re-read
        var reReadResp = await SendAuth(HttpMethod.Get, $"/api/v1/identity/groups/{id}");
        var reRead = await ParseJson(reReadResp);
        reRead.GetProperty("name").GetString().Should().Be("HttpOrg1Updated");
        reRead.GetProperty("description").GetString().Should().Be("Updated desc");

        // DELETE
        var deleteResp = await SendAuth(HttpMethod.Delete, $"/api/v1/identity/groups/{id}");
        deleteResp.StatusCode.Should().Be(HttpStatusCode.OK);

        // Verify deleted — should return error
        var afterDelete = await SendAuth(HttpMethod.Get, $"/api/v1/identity/groups/{id}");
        var afterBody = await ParseJson(afterDelete);
        afterBody.TryGetProperty("error", out _).Should().BeTrue("deleted group should return error");
    }

    [Fact]
    public async Task Groups_List_Returns200()
    {
        // Ensure at least one group exists
        await SendJson(HttpMethod.Post, "/api/v1/identity/groups",
            new { name = "HttpListGroup", groupType = "team" });

        var resp = await SendAuth(HttpMethod.Get, "/api/v1/identity/groups");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var json = await ParseJson(resp);
        json.ValueKind.Should().Be(JsonValueKind.Array);
        json.GetArrayLength().Should().BeGreaterThan(0);
    }

    // ══════════════════════════════════════════════
    //  Tree operations — hierarchy E2E
    // ══════════════════════════════════════════════

    [Fact]
    public async Task Groups_CreateChild_And_GetTree()
    {
        // Create parent org
        var parentResp = await SendJson(HttpMethod.Post, "/api/v1/identity/groups",
            new { name = "HttpTreeOrg", groupType = "organization" });
        var parentId = (await ParseJson(parentResp)).GetProperty("id").GetInt64();

        // Create child team under parent
        var childResp = await SendJson(HttpMethod.Post, $"/api/v1/identity/groups/{parentId}/children",
            new { name = "HttpTreeTeam", groupType = "team" });
        childResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var childId = (await ParseJson(childResp)).GetProperty("id").GetInt64();
        childId.Should().BeGreaterThan(0);

        // GET tree
        var treeResp = await SendAuth(HttpMethod.Get, $"/api/v1/identity/groups/{parentId}/tree");
        treeResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var tree = await ParseJson(treeResp);
        tree.GetProperty("id").GetInt64().Should().Be(parentId);
        tree.GetProperty("children").GetArrayLength().Should().BeGreaterThan(0);

        _output.WriteLine($"Tree root {parentId}, child {childId}");
    }

    [Fact]
    public async Task Groups_Children_ReturnsDirectChildren()
    {
        var parentResp = await SendJson(HttpMethod.Post, "/api/v1/identity/groups",
            new { name = "HttpChildrenOrg", groupType = "organization" });
        var parentId = (await ParseJson(parentResp)).GetProperty("id").GetInt64();

        await SendJson(HttpMethod.Post, $"/api/v1/identity/groups/{parentId}/children",
            new { name = "HttpChild1", groupType = "team" });
        await SendJson(HttpMethod.Post, $"/api/v1/identity/groups/{parentId}/children",
            new { name = "HttpChild2", groupType = "department" });

        var childrenResp = await SendAuth(HttpMethod.Get, $"/api/v1/identity/groups/{parentId}/children");
        childrenResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var children = await ParseJson(childrenResp);
        children.ValueKind.Should().Be(JsonValueKind.Array);
        children.GetArrayLength().Should().BeGreaterOrEqualTo(2);
    }

    [Fact]
    public async Task Groups_Path_ReturnsAncestors()
    {
        var orgResp = await SendJson(HttpMethod.Post, "/api/v1/identity/groups",
            new { name = "HttpPathOrg", groupType = "organization" });
        var orgId = (await ParseJson(orgResp)).GetProperty("id").GetInt64();

        var deptResp = await SendJson(HttpMethod.Post, $"/api/v1/identity/groups/{orgId}/children",
            new { name = "HttpPathDept", groupType = "department" });
        var deptId = (await ParseJson(deptResp)).GetProperty("id").GetInt64();

        var teamResp = await SendJson(HttpMethod.Post, $"/api/v1/identity/groups/{deptId}/children",
            new { name = "HttpPathTeam", groupType = "team" });
        var teamId = (await ParseJson(teamResp)).GetProperty("id").GetInt64();

        var pathResp = await SendAuth(HttpMethod.Get, $"/api/v1/identity/groups/{teamId}/path");
        pathResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var path = await ParseJson(pathResp);
        path.ValueKind.Should().Be(JsonValueKind.Array);
        path.GetArrayLength().Should().BeGreaterOrEqualTo(2, "path should include ancestors");

        _output.WriteLine($"Path for team {teamId}: {path.GetArrayLength()} ancestors");
    }

    [Fact]
    public async Task Groups_Move_ChangesParent()
    {
        var org1Resp = await SendJson(HttpMethod.Post, "/api/v1/identity/groups",
            new { name = "HttpMoveOrg1", groupType = "organization" });
        var org1Id = (await ParseJson(org1Resp)).GetProperty("id").GetInt64();

        var org2Resp = await SendJson(HttpMethod.Post, "/api/v1/identity/groups",
            new { name = "HttpMoveOrg2", groupType = "organization" });
        var org2Id = (await ParseJson(org2Resp)).GetProperty("id").GetInt64();

        var teamResp = await SendJson(HttpMethod.Post, $"/api/v1/identity/groups/{org1Id}/children",
            new { name = "HttpMoveTeam", groupType = "team" });
        var teamId = (await ParseJson(teamResp)).GetProperty("id").GetInt64();

        // Move team from org1 to org2
        var moveResp = await SendJson(HttpMethod.Post, $"/api/v1/identity/groups/{teamId}/move",
            new { newParentGroupId = org2Id });
        moveResp.StatusCode.Should().Be(HttpStatusCode.OK);

        // Verify via children of org2
        var children2 = await ParseJson(await SendAuth(HttpMethod.Get, $"/api/v1/identity/groups/{org2Id}/children"));
        children2.GetArrayLength().Should().BeGreaterThan(0, "team should be under org2 after move");
    }

    // ══════════════════════════════════════════════
    //  Membership — full lifecycle
    // ══════════════════════════════════════════════

    [Fact]
    public async Task Members_AddListUpdateRemove_FullCycle()
    {
        // Create group
        var groupResp = await SendJson(HttpMethod.Post, "/api/v1/identity/groups",
            new { name = "HttpMemberGroup", groupType = "team" });
        var groupId = (await ParseJson(groupResp)).GetProperty("id").GetInt64();
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        // ADD MEMBER
        var addResp = await SendJson(HttpMethod.Post, $"/api/v1/identity/groups/{groupId}/members",
            new { userId, role = "member" });
        addResp.StatusCode.Should().Be(HttpStatusCode.OK,
            "add member failed: {0}", await addResp.Content.ReadAsStringAsync());
        var addResult = await ParseJson(addResp);
        addResult.GetProperty("success").GetBoolean().Should().BeTrue();

        // LIST MEMBERS
        var listResp = await SendAuth(HttpMethod.Get, $"/api/v1/identity/groups/{groupId}/members");
        listResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var members = await ParseJson(listResp);
        members.ValueKind.Should().Be(JsonValueKind.Array);
        members.GetArrayLength().Should().BeGreaterThan(0);

        // UPDATE MEMBER ROLE
        var updateResp = await SendJson(HttpMethod.Put,
            $"/api/v1/identity/groups/{groupId}/members/{userId}",
            new { role = "admin" });
        updateResp.StatusCode.Should().Be(HttpStatusCode.OK);

        // REMOVE MEMBER
        var removeResp = await SendAuth(HttpMethod.Delete,
            $"/api/v1/identity/groups/{groupId}/members/{userId}");
        removeResp.StatusCode.Should().Be(HttpStatusCode.OK);

        // Verify removed
        var afterRemove = await ParseJson(
            await SendAuth(HttpMethod.Get, $"/api/v1/identity/groups/{groupId}/members"));
        // Should be empty or not contain userId
        if (afterRemove.ValueKind == JsonValueKind.Array)
        {
            foreach (var m in afterRemove.EnumerateArray())
            {
                if (m.TryGetProperty("UserId", out var uid) || m.TryGetProperty("userId", out uid))
                    uid.GetInt64().Should().NotBe(userId, "removed member should not appear");
            }
        }

        _output.WriteLine($"Member lifecycle complete for group {groupId}");
    }

    [Fact]
    public async Task UserGroups_ReturnsGroupsForUser()
    {
        var groupResp = await SendJson(HttpMethod.Post, "/api/v1/identity/groups",
            new { name = "HttpUserGroupsTeam", groupType = "team" });
        var groupId = (await ParseJson(groupResp)).GetProperty("id").GetInt64();
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        await SendJson(HttpMethod.Post, $"/api/v1/identity/groups/{groupId}/members",
            new { userId, role = "viewer" });

        var resp = await SendAuth(HttpMethod.Get, $"/api/v1/identity/groups/users/{userId}/groups");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var groups = await ParseJson(resp);
        groups.ValueKind.Should().Be(JsonValueKind.Array);
        groups.GetArrayLength().Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task IsMember_Check_ReturnsCorrectResult()
    {
        var groupResp = await SendJson(HttpMethod.Post, "/api/v1/identity/groups",
            new { name = "HttpIsMemberGroup", groupType = "team" });
        var groupId = (await ParseJson(groupResp)).GetProperty("id").GetInt64();
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        // Not a member yet
        var check1 = await ParseJson(
            await SendAuth(HttpMethod.Get, $"/api/v1/identity/groups/{groupId}/members/{userId}/check"));
        check1.GetProperty("isMember").GetBoolean().Should().BeFalse();

        // Add member
        await SendJson(HttpMethod.Post, $"/api/v1/identity/groups/{groupId}/members",
            new { userId, role = "member" });

        // Now is a member
        var check2 = await ParseJson(
            await SendAuth(HttpMethod.Get, $"/api/v1/identity/groups/{groupId}/members/{userId}/check"));
        check2.GetProperty("isMember").GetBoolean().Should().BeTrue();

        _output.WriteLine($"IsMember check passed for group {groupId}, user {userId}");
    }

    // ══════════════════════════════════════════════
    //  Ancestor membership — RFC/RBAC correctness
    // ══════════════════════════════════════════════

    [Fact]
    public async Task IsMember_ViaAncestor_InheritsMembership()
    {
        // Create hierarchy: org → dept → team
        var orgResp = await SendJson(HttpMethod.Post, "/api/v1/identity/groups",
            new { name = "HttpAncOrg", groupType = "organization" });
        var orgId = (await ParseJson(orgResp)).GetProperty("id").GetInt64();

        var deptResp = await SendJson(HttpMethod.Post, $"/api/v1/identity/groups/{orgId}/children",
            new { name = "HttpAncDept", groupType = "department" });
        var deptId = (await ParseJson(deptResp)).GetProperty("id").GetInt64();

        var teamResp = await SendJson(HttpMethod.Post, $"/api/v1/identity/groups/{deptId}/children",
            new { name = "HttpAncTeam", groupType = "team" });
        var teamId = (await ParseJson(teamResp)).GetProperty("id").GetInt64();

        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        // Add member to ORG level
        await SendJson(HttpMethod.Post, $"/api/v1/identity/groups/{orgId}/members",
            new { userId, role = "admin" });

        // Should be member of team via ancestor traversal
        var check = await ParseJson(
            await SendAuth(HttpMethod.Get, $"/api/v1/identity/groups/{teamId}/members/{userId}/check"));
        check.GetProperty("isMember").GetBoolean().Should().BeTrue(
            "member of ancestor org should be member of descendant team");

        _output.WriteLine($"Ancestor membership: org {orgId} → dept {deptId} → team {teamId}");
    }

    // ══════════════════════════════════════════════
    //  Cascade delete — subtree + memberships
    // ══════════════════════════════════════════════

    [Fact]
    public async Task Delete_CascadesSubtreeAndMemberships()
    {
        var orgResp = await SendJson(HttpMethod.Post, "/api/v1/identity/groups",
            new { name = "HttpCascadeOrg", groupType = "organization" });
        var orgId = (await ParseJson(orgResp)).GetProperty("id").GetInt64();

        var teamResp = await SendJson(HttpMethod.Post, $"/api/v1/identity/groups/{orgId}/children",
            new { name = "HttpCascadeTeam", groupType = "team" });
        var teamId = (await ParseJson(teamResp)).GetProperty("id").GetInt64();

        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        await SendJson(HttpMethod.Post, $"/api/v1/identity/groups/{teamId}/members",
            new { userId, role = "member" });

        // Delete org — should cascade delete team + memberships
        var deleteResp = await SendAuth(HttpMethod.Delete, $"/api/v1/identity/groups/{orgId}");
        deleteResp.StatusCode.Should().Be(HttpStatusCode.OK);

        // Team should be gone
        var teamRead = await ParseJson(
            await SendAuth(HttpMethod.Get, $"/api/v1/identity/groups/{teamId}"));
        teamRead.TryGetProperty("error", out _).Should().BeTrue("child team should be deleted");

        _output.WriteLine($"Cascade delete: org {orgId} → team {teamId} both removed");
    }

    // ══════════════════════════════════════════════
    //  Helpers
    // ══════════════════════════════════════════════

    private async Task<HttpResponseMessage> SendAuth(HttpMethod method, string path)
    {
        var req = WithAuth(new HttpRequestMessage(method, path));
        return await _http.SendAsync(req);
    }

    private async Task<HttpResponseMessage> SendJson(HttpMethod method, string path, object body)
    {
        var req = WithAuth(new HttpRequestMessage(method, path)
        {
            Content = JsonContent.Create(body)
        });
        return await _http.SendAsync(req);
    }

    private static async Task<JsonElement> ParseJson(HttpResponseMessage resp)
    {
        var body = await resp.Content.ReadAsStringAsync();
        return JsonDocument.Parse(body).RootElement;
    }
}
