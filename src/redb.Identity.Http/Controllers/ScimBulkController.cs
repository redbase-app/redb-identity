using redb.Identity.Contracts.Scim;
using redb.Identity.Contracts.Routes;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// SCIM 2.0 Bulk endpoint (RFC 7644 §3.7).
/// Forwards to <c>direct-vm://identity-scim-bulk</c> route.
/// </summary>
[Route("Bulk")]
public class ScimBulkController : ScimControllerBase
{
    [HttpPost]
    public async Task<object?> Bulk([FromBody] ScimBulkRequest request)
    {
        if (ValidateRequest(request) is { } problem) return problem;
        return await Forward(IdentityEndpoints.ScimBulk, "process", request);
    }
}
