using redb.Identity.Contracts.Roles;
using redb.Identity.Contracts.Routes;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// B.3 — REST admin API for the Roles registry.
/// Forwards to <c>direct-vm://identity-manage-roles</c>.
/// </summary>
[Route("roles")]
public class RolesController : IdentityControllerBase
{
    [HttpGet]
    public async Task<object?> Search(
        [FromQuery("query")] string? query = null,
        [FromQuery("audience")] string? audience = null,
        [FromQuery("applicationId")] string? applicationId = null,
        [FromQuery("offset")] int offset = 0,
        [FromQuery("count")] int count = 25)
    {
        var body = new Dictionary<string, object?>
        {
            ["query"] = query,
            ["audience"] = audience,
            ["applicationId"] = applicationId,
            ["offset"] = offset,
            ["count"] = count
        };
        return await Forward(IdentityEndpoints.ManageRoles, "search", body);
    }

    [HttpGet("{id}")]
    public async Task<object?> Get([FromRoute("id")] string id)
    {
        return await Forward(IdentityEndpoints.ManageRoles, "get",
            new Dictionary<string, object> { ["id"] = id });
    }

    [HttpPost]
    public async Task<object?> Create([FromBody] CreateRoleRequest request)
    {
        if (ValidateRequest(request) is { } problem) return problem;
        return await Forward(IdentityEndpoints.ManageRoles, "create", request);
    }

    [HttpPut("{id}")]
    public async Task<object?> Update([FromRoute("id")] string id, [FromBody] UpdateRoleRequest request)
    {
        var body = new Dictionary<string, object?>
        {
            ["id"] = id,
            ["displayName"] = request.DisplayName,
            ["description"] = request.Description,
        };
        return await Forward(IdentityEndpoints.ManageRoles, "update", body);
    }

    [HttpDelete("{id}")]
    public async Task<object?> Delete([FromRoute("id")] string id)
    {
        return await Forward(IdentityEndpoints.ManageRoles, "delete",
            new Dictionary<string, object> { ["id"] = id });
    }

    [HttpGet("{id}/assignees")]
    public async Task<object?> ListAssignees([FromRoute("id")] string id)
    {
        return await Forward(IdentityEndpoints.ManageRoles, "list-assignees",
            new Dictionary<string, object> { ["roleId"] = id });
    }

    [HttpPost("{id}/users")]
    public async Task<object?> AssignUser([FromRoute("id")] string id, [FromBody] Dictionary<string, object?> body)
    {
        var dict = new Dictionary<string, object?>(body) { ["roleId"] = id };
        return await Forward(IdentityEndpoints.ManageRoles, "assign-user", dict);
    }

    [HttpDelete("{id}/users/{userId}")]
    public async Task<object?> UnassignUser([FromRoute("id")] string id, [FromRoute("userId")] string userId)
    {
        return await Forward(IdentityEndpoints.ManageRoles, "unassign-user",
            new Dictionary<string, object> { ["roleId"] = id, ["userId"] = userId });
    }

    [HttpPost("{id}/groups")]
    public async Task<object?> AssignGroup([FromRoute("id")] string id, [FromBody] Dictionary<string, object?> body)
    {
        var dict = new Dictionary<string, object?>(body) { ["roleId"] = id };
        return await Forward(IdentityEndpoints.ManageRoles, "assign-group", dict);
    }

    [HttpDelete("{id}/groups/{groupId}")]
    public async Task<object?> UnassignGroup([FromRoute("id")] string id, [FromRoute("groupId")] string groupId)
    {
        return await Forward(IdentityEndpoints.ManageRoles, "unassign-group",
            new Dictionary<string, object> { ["roleId"] = id, ["groupId"] = groupId });
    }

    [HttpGet("{id}/scopes")]
    public async Task<object?> ListScopes([FromRoute("id")] string id)
    {
        return await Forward(IdentityEndpoints.ManageRoles, "list-scopes",
            new Dictionary<string, object> { ["roleId"] = id });
    }

    [HttpPost("{id}/scopes")]
    public async Task<object?> AttachScope([FromRoute("id")] string id, [FromBody] Dictionary<string, object?> body)
    {
        var dict = new Dictionary<string, object?>(body) { ["roleId"] = id };
        return await Forward(IdentityEndpoints.ManageRoles, "attach-scope", dict);
    }

    [HttpDelete("{id}/scopes/{scopeId}")]
    public async Task<object?> DetachScope([FromRoute("id")] string id, [FromRoute("scopeId")] string scopeId)
    {
        return await Forward(IdentityEndpoints.ManageRoles, "detach-scope",
            new Dictionary<string, object> { ["roleId"] = id, ["scopeId"] = scopeId });
    }
}
