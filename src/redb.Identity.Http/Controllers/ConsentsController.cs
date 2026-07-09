using redb.Identity.Contracts.Routes;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

[Route("consents")]
public class ConsentsController : IdentityControllerBase
{
    [HttpGet]
    public async Task<object?> ListByUser([FromQuery("userId")] string userId)
    {
        return await Forward(IdentityEndpoints.ManageConsents, "list",
            new Dictionary<string, object?> { ["userId"] = long.TryParse(userId, out var id) ? id : 0 });
    }

    [HttpDelete]
    public async Task<object?> Revoke(
        [FromQuery("userId")] string userId,
        [FromQuery("applicationId")] string applicationId)
    {
        return await Forward(IdentityEndpoints.ManageConsents, "revoke",
            new Dictionary<string, object?>
            {
                ["userId"] = long.TryParse(userId, out var uid) ? uid : 0,
                ["applicationId"] = long.TryParse(applicationId, out var aid) ? aid : 0
            });
    }

    [HttpDelete("all")]
    public async Task<object?> RevokeAll([FromQuery("userId")] string userId)
    {
        return await Forward(IdentityEndpoints.ManageConsents, "revoke-all",
            new Dictionary<string, object?> { ["userId"] = long.TryParse(userId, out var id) ? id : 0 });
    }
}
