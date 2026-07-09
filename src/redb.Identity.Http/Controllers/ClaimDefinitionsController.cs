using redb.Identity.Contracts.ClaimDefinitions;
using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Routes;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// S2 — admin CRUD for claim definitions
/// (<see cref="IdentityEndpoints.ManageClaimDefinitions"/>).
/// </summary>
[Route("claim-definitions")]
public sealed class ClaimDefinitionsController : IdentityControllerBase
{
    [HttpGet]
    public async Task<object?> List(
        [FromQuery("offset")] int offset = 0,
        [FromQuery("count")] int count = 50,
        [FromQuery("scope")] string? scope = null,
        [FromQuery("applicationId")] string? applicationId = null)
    {
        var body = new Dictionary<string, object?>
        {
            ["Offset"] = offset,
            ["Count"] = count,
        };
        if (!string.IsNullOrEmpty(scope)) body["scope"] = scope;
        if (!string.IsNullOrEmpty(applicationId)) body["applicationId"] = applicationId;
        return await Forward(IdentityEndpoints.ManageClaimDefinitions, "list", body);
    }

    [HttpGet("{id}")]
    public async Task<object?> Get([FromRoute("id")] string id)
    {
        return await Forward(IdentityEndpoints.ManageClaimDefinitions, "get",
            new Dictionary<string, object> { ["id"] = id });
    }

    [HttpPost]
    public async Task<object?> Create([FromBody] CreateClaimDefinitionRequest request)
    {
        if (ValidateRequest(request) is { } problem) return problem;
        return await Forward(IdentityEndpoints.ManageClaimDefinitions, "create", request);
    }

    [HttpPut("{id}")]
    public async Task<object?> Update([FromRoute("id")] string id, [FromBody] UpdateClaimDefinitionRequest request)
    {
        if (long.TryParse(id, out var numericId)) request.Id = numericId;
        if (ValidateRequest(request) is { } problem) return problem;
        return await Forward(IdentityEndpoints.ManageClaimDefinitions, "update", request);
    }

    [HttpDelete("{id}")]
    public async Task<object?> Delete([FromRoute("id")] string id)
    {
        return await Forward(IdentityEndpoints.ManageClaimDefinitions, "delete",
            new Dictionary<string, object> { ["id"] = id });
    }
}
