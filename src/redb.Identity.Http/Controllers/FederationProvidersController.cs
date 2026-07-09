using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Federation;
using redb.Identity.Contracts.Routes;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// H8 (v1.0 DoD §4 gap (e)): REST admin API for PROPS-stored federation providers.
/// Forwards to <c>direct-vm://identity-manage-federation-providers</c>. Client secrets
/// are encrypted at rest via DataProtection (purpose
/// <c>redb.identity.federation-provider-secret</c>) and never returned in responses.
/// </summary>
[Route("federation-providers")]
public class FederationProvidersController : IdentityControllerBase
{
    [HttpGet]
    public async Task<object?> List(
        [FromQuery("offset")] int offset = 0,
        [FromQuery("count")] int count = 25)
    {
        var listReq = new ListRequest { Offset = offset, Count = count };
        return await Forward(IdentityEndpoints.ManageFederationProviders, "list", listReq);
    }

    [HttpGet("{id}")]
    public async Task<object?> Get([FromRoute("id")] string id)
        => await Forward(IdentityEndpoints.ManageFederationProviders, "read", ParseIdBody(id));

    [HttpPost]
    public async Task<object?> Create([FromBody] CreateFederationProviderRequest request)
    {
        if (ValidateRequest(request) is { } problem) return problem;
        return await Forward(IdentityEndpoints.ManageFederationProviders, "create", request);
    }

    [HttpPut("{id}")]
    public async Task<object?> Update(
        [FromRoute("id")] string id,
        [FromBody] UpdateFederationProviderRequest request)
    {
        request.Id = id;
        if (ValidateRequest(request) is { } problem) return problem;
        return await Forward(IdentityEndpoints.ManageFederationProviders, "update", request);
    }

    [HttpDelete("{id}")]
    public async Task<object?> Delete([FromRoute("id")] string id)
        => await Forward(IdentityEndpoints.ManageFederationProviders, "delete", ParseIdBody(id));
}
