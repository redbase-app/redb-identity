using redb.Identity.Contracts.Groups;
using redb.Identity.Contracts.Routes;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// REST management API for groups/organizations.
/// Forwards to <c>direct-vm://identity-manage-groups</c> route.
/// </summary>
[Route("groups")]
public class GroupsController : IdentityControllerBase
{
    [HttpGet]
    public async Task<object?> List(
        [FromQuery("offset")] int offset = 0,
        [FromQuery("count")] int count = 25)
    {
        return await Forward(IdentityEndpoints.ManageGroups, "list",
            new Dictionary<string, object> { ["offset"] = offset, ["count"] = count });
    }

    /// <summary>
    /// B.2 — flat paginated search across ALL groups (root + nested),
    /// optionally filtered by name pattern and groupType. Each row carries a
    /// member-count badge resolved server-side in a single bulk query.
    /// </summary>
    [HttpGet("search")]
    public async Task<object?> Search(
        [FromQuery("query")] string? query = null,
        [FromQuery("groupType")] string? groupType = null,
        [FromQuery("offset")] int offset = 0,
        [FromQuery("count")] int count = 25)
    {
        var body = new Dictionary<string, object?>
        {
            ["query"] = query,
            ["groupType"] = groupType,
            ["offset"] = offset,
            ["count"] = count
        };
        return await Forward(IdentityEndpoints.ManageGroups, "search", body);
    }

    [HttpGet("{id}")]
    public async Task<object?> Get([FromRoute("id")] string id)
    {
        return await Forward(IdentityEndpoints.ManageGroups, "read",
            ParseIdBody(id, numericKey: "groupId", stringKey: "groupId"));
    }

    [HttpPost]
    public async Task<object?> Create([FromBody] CreateGroupRequest request)
    {
        if (ValidateRequest(request) is { } problem) return problem;
        return await Forward(IdentityEndpoints.ManageGroups, "create", new Dictionary<string, object?>
        {
            ["name"] = request.Name,
            ["groupType"] = request.GroupType,
            ["description"] = request.Description,
            ["parentGroupId"] = request.ParentGroupId
        });
    }

    [HttpPost("{id}/children")]
    public async Task<object?> CreateChild([FromRoute("id")] string id, [FromBody] CreateGroupRequest request)
    {
        if (ValidateRequest(request) is { } problem) return problem;
        var parentId = long.TryParse(id, out var pid) ? pid : 0L;
        return await Forward(IdentityEndpoints.ManageGroups, "create-child", new Dictionary<string, object?>
        {
            ["parentGroupId"] = parentId,
            ["name"] = request.Name,
            ["groupType"] = request.GroupType,
            ["description"] = request.Description
        });
    }

    [HttpPut("{id}")]
    public async Task<object?> Update([FromRoute("id")] string id, [FromBody] UpdateGroupRequest request)
    {
        if (ValidateRequest(request) is { } problem) return problem;
        var numericId = long.TryParse(id, out var nid) ? nid : 0L;
        return await Forward(IdentityEndpoints.ManageGroups, "update", new Dictionary<string, object?>
        {
            ["groupId"] = numericId,
            ["name"] = request.Name,
            ["groupType"] = request.GroupType,
            ["description"] = request.Description
        });
    }

    [HttpDelete("{id}")]
    public async Task<object?> Delete([FromRoute("id")] string id)
    {
        return await Forward(IdentityEndpoints.ManageGroups, "delete",
            ParseIdBody(id, numericKey: "groupId", stringKey: "groupId"));
    }

    [HttpPost("{id}/move")]
    public async Task<object?> Move([FromRoute("id")] string id, [FromBody] MoveGroupRequest request)
    {
        if (ValidateRequest(request) is { } problem) return problem;
        var numericId = long.TryParse(id, out var nid) ? nid : 0L;
        return await Forward(IdentityEndpoints.ManageGroups, "move", new Dictionary<string, object?>
        {
            ["groupId"] = numericId,
            ["newParentGroupId"] = request.NewParentGroupId
        });
    }

    [HttpGet("{id}/tree")]
    public async Task<object?> Tree([FromRoute("id")] string id)
    {
        return await Forward(IdentityEndpoints.ManageGroups, "tree",
            ParseIdBody(id, numericKey: "groupId", stringKey: "groupId"));
    }

    [HttpGet("{id}/path")]
    public async Task<object?> Path([FromRoute("id")] string id)
    {
        return await Forward(IdentityEndpoints.ManageGroups, "path",
            ParseIdBody(id, numericKey: "groupId", stringKey: "groupId"));
    }

    [HttpGet("{id}/children")]
    public async Task<object?> Children([FromRoute("id")] string id)
    {
        return await Forward(IdentityEndpoints.ManageGroups, "children",
            ParseIdBody(id, numericKey: "groupId", stringKey: "groupId"));
    }

    [HttpGet("{id}/members")]
    public async Task<object?> ListMembers([FromRoute("id")] string id)
    {
        return await Forward(IdentityEndpoints.ManageGroups, "list-members",
            ParseIdBody(id, numericKey: "groupId", stringKey: "groupId"));
    }

    [HttpPost("{id}/members")]
    public async Task<object?> AddMember([FromRoute("id")] string id, [FromBody] AddMemberRequest request)
    {
        if (ValidateRequest(request) is { } problem) return problem;
        var numericId = long.TryParse(id, out var nid) ? nid : 0L;
        return await Forward(IdentityEndpoints.ManageGroups, "add-member", new Dictionary<string, object?>
        {
            ["groupId"] = numericId,
            ["userId"] = request.UserId,
            ["role"] = request.Role,
            ["expiresAt"] = request.ExpiresAt
        });
    }

    [HttpPut("{id}/members/{userId}")]
    public async Task<object?> UpdateMember(
        [FromRoute("id")] string id, [FromRoute("userId")] string userId,
        [FromBody] UpdateMemberRequest request)
    {
        if (ValidateRequest(request) is { } problem) return problem;
        return await Forward(IdentityEndpoints.ManageGroups, "update-member", new Dictionary<string, object?>
        {
            ["groupId"] = long.TryParse(id, out var gid) ? gid : 0L,
            ["userId"] = long.TryParse(userId, out var uid) ? uid : 0L,
            ["role"] = request.Role
        });
    }

    [HttpDelete("{id}/members/{userId}")]
    public async Task<object?> RemoveMember([FromRoute("id")] string id, [FromRoute("userId")] string userId)
    {
        return await Forward(IdentityEndpoints.ManageGroups, "remove-member",
            new Dictionary<string, object?>
            {
                ["groupId"] = long.TryParse(id, out var gid) ? gid : 0,
                ["userId"] = long.TryParse(userId, out var uid) ? uid : 0
            });
    }

    [HttpGet("users/{userId}/groups")]
    public async Task<object?> UserGroups([FromRoute("userId")] string userId)
    {
        return await Forward(IdentityEndpoints.ManageGroups, "user-groups",
            new Dictionary<string, object?>
            {
                ["userId"] = long.TryParse(userId, out var uid) ? uid : 0L
            });
    }

    [HttpGet("{id}/members/{userId}/check")]
    public async Task<object?> IsMember([FromRoute("id")] string id, [FromRoute("userId")] string userId)
    {
        return await Forward(IdentityEndpoints.ManageGroups, "is-member",
            new Dictionary<string, object?>
            {
                ["groupId"] = long.TryParse(id, out var gid) ? gid : 0L,
                ["userId"] = long.TryParse(userId, out var uid) ? uid : 0L
            });
    }
}
