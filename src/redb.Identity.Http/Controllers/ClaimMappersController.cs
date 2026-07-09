using redb.Identity.Contracts.ClaimMappers;
using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Routes;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// H5 (v1.0 DoD §5): REST admin API for declarative claim mapping rules.
/// Forwards to <c>direct-vm://identity-manage-claim-mappers</c>.
/// </summary>
[Route("claim-mappers")]
public class ClaimMappersController : IdentityControllerBase
{
    /// <summary>
    /// Lists claim mappers. Optional <c>owner</c> filter:
    /// <c>"global"</c>, <c>"application:{id}"</c>, <c>"scope:{id}"</c>; omit for all.
    /// </summary>
    [HttpGet]
    public async Task<object?> List(
        [FromQuery("owner")] string? owner = null,
        [FromQuery("offset")] int offset = 0,
        [FromQuery("count")] int count = 25)
    {
        var body = new Dictionary<string, object?>
        {
            ["Offset"] = offset,
            ["Count"] = count,
            ["owner"] = owner,
        };
        // ListRequest projection lives in body; processor reads owner from body too.
        var listReq = new ListRequest { Offset = offset, Count = count };
        // Pass owner via body extra-field by sending a dict; processor handles both shapes.
        var compositeBody = new Dictionary<string, object?>
        {
            ["offset"] = listReq.Offset,
            ["count"] = listReq.Count,
            ["owner"] = owner,
        };
        return await Forward(IdentityEndpoints.ManageClaimMappers, "list", compositeBody);
    }

    [HttpGet("{id}")]
    public async Task<object?> Get([FromRoute("id")] string id)
        => await Forward(IdentityEndpoints.ManageClaimMappers, "read", ParseIdBody(id));

    [HttpPost]
    public async Task<object?> Create([FromBody] CreateClaimMapperRequest request)
    {
        if (ValidateRequest(request) is { } problem) return problem;
        return await Forward(IdentityEndpoints.ManageClaimMappers, "create", request);
    }

    [HttpPut("{id}")]
    public async Task<object?> Update([FromRoute("id")] string id, [FromBody] UpdateClaimMapperRequest request)
    {
        request.Id = id;
        if (ValidateRequest(request) is { } problem) return problem;
        return await Forward(IdentityEndpoints.ManageClaimMappers, "update", request);
    }

    [HttpDelete("{id}")]
    public async Task<object?> Delete([FromRoute("id")] string id)
        => await Forward(IdentityEndpoints.ManageClaimMappers, "delete", ParseIdBody(id));
}
