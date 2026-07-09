using redb.Identity.Contracts.ClaimMappers;
using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Routes;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// H5 (v1.0 DoD §5): REST admin API for reusable Client Scopes (mapper bundles)
/// AND for Application↔Scope assignments.
/// Forwards to <c>direct-vm://identity-manage-claim-scopes</c>.
/// </summary>
[Route("claim-scopes")]
public class ClaimScopesController : IdentityControllerBase
{
    [HttpGet]
    public async Task<object?> List(
        [FromQuery("offset")] int offset = 0,
        [FromQuery("count")] int count = 25)
        => await Forward(IdentityEndpoints.ManageClaimScopes, "list",
            new ListRequest { Offset = offset, Count = count });

    [HttpGet("{id}")]
    public async Task<object?> Get([FromRoute("id")] string id)
        => await Forward(IdentityEndpoints.ManageClaimScopes, "read", ParseIdBody(id, stringKey: "name"));

    [HttpPost]
    public async Task<object?> Create([FromBody] CreateClaimScopeRequest request)
    {
        if (ValidateRequest(request) is { } problem) return problem;
        return await Forward(IdentityEndpoints.ManageClaimScopes, "create", request);
    }

    [HttpPut("{id}")]
    public async Task<object?> Update([FromRoute("id")] string id, [FromBody] UpdateClaimScopeRequest request)
    {
        request.Id = id;
        if (ValidateRequest(request) is { } problem) return problem;
        return await Forward(IdentityEndpoints.ManageClaimScopes, "update", request);
    }

    [HttpDelete("{id}")]
    public async Task<object?> Delete([FromRoute("id")] string id)
        => await Forward(IdentityEndpoints.ManageClaimScopes, "delete", ParseIdBody(id, stringKey: "name"));

    // ── Application ↔ Scope assignments ──

    /// <summary>Lists scopes assigned to a given Application.</summary>
    [HttpGet("assignments")]
    public async Task<object?> ListAssignments([FromQuery("applicationId")] string applicationId)
    {
        var body = new Dictionary<string, object?> { ["applicationId"] = applicationId };
        return await Forward(IdentityEndpoints.ManageClaimScopes, "list-assignments", body);
    }

    /// <summary>Assigns a scope to an Application (idempotent; returns existing on duplicate).</summary>
    [HttpPost("assignments")]
    public async Task<object?> Assign([FromBody] AssignClaimScopeRequest request)
    {
        if (ValidateRequest(request) is { } problem) return problem;
        return await Forward(IdentityEndpoints.ManageClaimScopes, "assign", request);
    }

    /// <summary>Removes a scope assignment by composite key.</summary>
    [HttpDelete("assignments")]
    public async Task<object?> Unassign(
        [FromQuery("applicationId")] string applicationId,
        [FromQuery("scopeId")] string scopeId)
    {
        var body = new Dictionary<string, object?>
        {
            ["applicationId"] = applicationId,
            ["scopeId"] = scopeId,
        };
        return await Forward(IdentityEndpoints.ManageClaimScopes, "unassign", body);
    }
}
