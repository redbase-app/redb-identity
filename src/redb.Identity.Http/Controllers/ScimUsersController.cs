using redb.Identity.Contracts.Scim;
using redb.Identity.Contracts.Routes;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// SCIM 2.0 Users endpoint (RFC 7644 §3.2–3.5).
/// Forwards to <c>direct-vm://identity-scim-users</c> route.
/// </summary>
[Route("Users")]
public class ScimUsersController : ScimControllerBase
{
    [HttpGet]
    public async Task<object?> List(
        [FromQuery("startIndex")] int startIndex = 1,
        [FromQuery("count")] int count = 25,
        [FromQuery("filter")] string? filter = null,
        [FromQuery("sortBy")] string? sortBy = null,
        [FromQuery("sortOrder")] string? sortOrder = null)
    {
        return await Forward(IdentityEndpoints.ScimUsers, "list",
            new Dictionary<string, object?>
            {
                ["startIndex"] = startIndex,
                ["count"] = count,
                ["filter"] = filter,
                ["sortBy"] = sortBy,
                ["sortOrder"] = sortOrder
            });
    }

    [HttpGet("{id}")]
    public async Task<object?> Get([FromRoute("id")] string id)
    {
        return await Forward(IdentityEndpoints.ScimUsers, "read",
            new Dictionary<string, object?> { ["id"] = id });
    }

    [HttpPost]
    public async Task<object?> Create([FromBody] ScimUser user)
    {
        if (ValidateRequest(user) is { } problem) return problem;
        return await Forward(IdentityEndpoints.ScimUsers, "create", user);
    }

    [HttpPut("{id}")]
    public async Task<object?> Replace([FromRoute("id")] string id, [FromBody] ScimUser user)
    {
        user.Id = id;
        if (ValidateRequest(user) is { } problem) return problem;
        return await Forward(IdentityEndpoints.ScimUsers, "replace", user);
    }

    [HttpPatch("{id}")]
    public async Task<object?> Patch([FromRoute("id")] string id, [FromBody] ScimPatchRequest patch)
    {
        if (ValidateRequest(patch) is { } problem) return problem;
        return await Forward(IdentityEndpoints.ScimUsers, "patch",
            new Dictionary<string, object?> { ["id"] = id, ["patch"] = patch });
    }

    [HttpDelete("{id}")]
    public async Task<object?> Delete([FromRoute("id")] string id)
    {
        return await Forward(IdentityEndpoints.ScimUsers, "delete",
            new Dictionary<string, object?> { ["id"] = id });
    }
}
