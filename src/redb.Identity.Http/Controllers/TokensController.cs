using redb.Identity.Contracts.Routes;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// REST management API for token administration: listing, revoking, pruning.
/// Forwards to <c>direct-vm://identity-manage-tokens</c> route.
/// </summary>
[Route("tokens")]
public class TokensController : IdentityControllerBase
{
    [HttpGet]
    public async Task<object?> List(
        [FromQuery("subject")] string? subject = null,
        [FromQuery("offset")] int offset = 0,
        [FromQuery("count")] int count = 20)
    {
        var body = new Dictionary<string, object?> { ["offset"] = offset, ["count"] = count };
        if (subject is not null)
            body["subject"] = subject;
        return await Forward(IdentityEndpoints.ManageTokens, "list", body);
    }

    [HttpDelete("{id}")]
    public async Task<object?> Revoke([FromRoute("id")] string id)
    {
        return await Forward(IdentityEndpoints.ManageTokens, "revoke",
            ParseIdBody(id, numericKey: "tokenId", stringKey: "tokenId"));
    }

    [HttpPost("revoke-by-subject")]
    public async Task<object?> RevokeBySubject([FromBody] Dictionary<string, object> request)
    {
        return await Forward(IdentityEndpoints.ManageTokens, "revoke-by-user", request);
    }

    [HttpPost("prune")]
    public async Task<object?> Prune([FromQuery("dryRun")] string? dryRun = null)
    {
        var body = new Dictionary<string, object?>();
        if (bool.TryParse(dryRun, out var dr) && dr)
            body["dryRun"] = true;
        return await Forward(IdentityEndpoints.ManageTokens, "prune", body);
    }
}
