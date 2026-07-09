using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Scopes;
using redb.Identity.Contracts.Routes;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// REST management API for OAuth 2.0 scopes.
/// Forwards to <c>direct-vm://identity-manage-scopes</c> route.
/// </summary>
[Route("scopes")]
public class ScopesController : IdentityControllerBase
{
    [HttpGet]
    public async Task<object?> List(
        [FromQuery("offset")] int offset = 0,
        [FromQuery("count")] int count = 25)
    {
        return await Forward(IdentityEndpoints.ManageScopes, "list",
            new ListRequest { Offset = offset, Count = count });
    }

    [HttpGet("{id}")]
    public async Task<object?> Get([FromRoute("id")] string id)
    {
        return await Forward(IdentityEndpoints.ManageScopes, "read", ParseIdBody(id, stringKey: "name"));
    }

    [HttpPost]
    public async Task<object?> Create([FromBody] CreateScopeRequest request)
    {
        if (ValidateRequest(request) is { } problem) return problem;
        return await Forward(IdentityEndpoints.ManageScopes, "create", request);
    }

    [HttpPut("{id}")]
    public async Task<object?> Update([FromRoute("id")] string id, [FromBody] UpdateScopeRequest request)
    {
        request.Id = id;
        if (ValidateRequest(request) is { } problem) return problem;
        return await Forward(IdentityEndpoints.ManageScopes, "update", request);
    }

    [HttpDelete("{id}")]
    public async Task<object?> Delete([FromRoute("id")] string id)
    {
        return await Forward(IdentityEndpoints.ManageScopes, "delete", ParseIdBody(id, stringKey: "name"));
    }
}
