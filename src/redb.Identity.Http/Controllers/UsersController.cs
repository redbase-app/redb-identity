using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Users;
using redb.Identity.Contracts.Routes;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// REST management API for user accounts.
/// Forwards to <c>direct-vm://identity-manage-users</c> route.
/// </summary>
[Route("users")]
public class UsersController : IdentityControllerBase
{
    [HttpGet]
    public async Task<object?> List(
        [FromQuery("offset")] int offset = 0,
        [FromQuery("count")] int count = 25)
    {
        return await Forward(IdentityEndpoints.ManageUsers, "list",
            new ListRequest { Offset = offset, Count = count });
    }

    [HttpGet("{id}")]
    public async Task<object?> Get([FromRoute("id")] string id)
    {
        return await Forward(IdentityEndpoints.ManageUsers, "read", ParseIdBody(id, stringKey: "login"));
    }

    [HttpPost]
    public async Task<object?> Create([FromBody] CreateUserRequest request)
    {
        if (ValidateRequest(request) is { } problem) return problem;
        return await Forward(IdentityEndpoints.ManageUsers, "create", request);
    }

    [HttpPut("{id}")]
    public async Task<object?> Update([FromRoute("id")] string id, [FromBody] UpdateUserRequest request)
    {
        if (long.TryParse(id, out var numericId))
            request.Id = numericId;
        if (ValidateRequest(request) is { } problem) return problem;
        return await Forward(IdentityEndpoints.ManageUsers, "update", request);
    }

    [HttpDelete("{id}")]
    public async Task<object?> Delete([FromRoute("id")] string id)
    {
        return await Forward(IdentityEndpoints.ManageUsers, "delete", ParseIdBody(id, stringKey: "login"));
    }

    [HttpPost("{id}/change-password")]
    public async Task<object?> ChangePassword([FromRoute("id")] string id, [FromBody] ChangePasswordRequest request)
    {
        if (long.TryParse(id, out var numericId))
            request.Id = numericId;
        if (ValidateRequest(request) is { } problem) return problem;
        return await Forward(IdentityEndpoints.ManageUsers, "change-password", request);
    }

    /// <summary>
    /// Admin-side password reset (no OldPassword challenge — admin scope IS the
    /// authorization). Use for "user forgot the password and the operator
    /// resets it out-of-band" — the regular user-self change-password flow
    /// stays as it was.
    /// </summary>
    [HttpPost("{id}/admin-reset-password")]
    public async Task<object?> AdminResetPassword([FromRoute("id")] string id, [FromBody] AdminResetPasswordRequest request)
    {
        if (long.TryParse(id, out var numericId))
            request.Id = numericId;
        if (ValidateRequest(request) is { } problem) return problem;
        return await Forward(IdentityEndpoints.ManageUsers, "admin-reset-password", request);
    }

    [HttpGet("search")]
    public async Task<object?> Search(
        [FromQuery("query")] string query,
        [FromQuery("offset")] string? offset = null,
        [FromQuery("count")] string? count = null)
    {
        var body = new Dictionary<string, object> { ["query"] = query };
        if (!string.IsNullOrEmpty(offset)) body["offset"] = offset;
        if (!string.IsNullOrEmpty(count)) body["count"] = count;
        return await Forward(IdentityEndpoints.ManageUsers, "search", body);
    }
}
