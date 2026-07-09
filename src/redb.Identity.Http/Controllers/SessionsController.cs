using redb.Identity.Contracts.Routes;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

[Route("sessions")]
public class SessionsController : IdentityControllerBase
{
    [HttpGet]
    public async Task<object?> List(
        [FromQuery("userId")] string? userId = null,
        [FromQuery("offset")] string? offset = null,
        [FromQuery("count")] string? count = null)
    {
        // userId omitted → admin-wide browse of active sessions (WSO2-style
        // default view, paginated). userId present → targeted per-user list.
        if (string.IsNullOrEmpty(userId))
        {
            return await Forward(IdentityEndpoints.ManageSessions, "list-all",
                new Dictionary<string, object?>
                {
                    ["offset"] = long.TryParse(offset, out var o) ? o : 0,
                    ["count"] = long.TryParse(count, out var c) ? c : 25
                });
        }
        return await Forward(IdentityEndpoints.ManageSessions, "list",
            new Dictionary<string, object?> { ["userId"] = long.TryParse(userId, out var id) ? id : 0 });
    }

    [HttpDelete]
    public async Task<object?> Revoke([FromQuery("sessionId")] string sessionId)
    {
        return await Forward(IdentityEndpoints.ManageSessions, "revoke",
            new Dictionary<string, object?> { ["sessionId"] = long.TryParse(sessionId, out var id) ? id : 0 });
    }

    [HttpDelete("all")]
    public async Task<object?> RevokeAll(
        [FromQuery("userId")] string userId,
        [FromQuery("dryRun")] string? dryRun = null)
    {
        var body = new Dictionary<string, object?>
        {
            ["userId"] = long.TryParse(userId, out var id) ? id : 0
        };
        if (bool.TryParse(dryRun, out var dr) && dr)
            body["dryRun"] = true;
        return await Forward(IdentityEndpoints.ManageSessions, "revoke-all", body);
    }

    [HttpPost("logout")]
    public async Task<object?> Logout([FromQuery("userId")] string userId)
    {
        return await Forward(IdentityEndpoints.ManageSessions, "logout",
            new Dictionary<string, object?> { ["userId"] = long.TryParse(userId, out var id) ? id : 0 });
    }
}
