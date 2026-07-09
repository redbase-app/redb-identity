using redb.Identity.Contracts.Routes;
using redb.Identity.Contracts.Sessions;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// W6-0: Backchannel revoked-sids list. Consumed by Relying Parties (incl. our own
/// <c>Identity.Web</c>) to invalidate cookie sessions across replicas where the
/// OIDC backchannel logout (<c>/bcl/sink</c>) push alone is not sufficient.
/// <para>
/// Both endpoints require the <c>identity:manage</c> scope (enforced by the same
/// <c>ManagementBearerAuth</c> chain as <c>/sessions</c>). RPs configure their poller
/// with a management token issued via client_credentials.
/// </para>
/// </summary>
[Route("revoked-sids")]
public class RevokedSidsController : IdentityControllerBase
{
    /// <summary>
    /// Publishes a new revocation entry (single sid, single sub, or both). Server clamps
    /// <c>ExpiresAt</c> to the configured <c>RevokedSidsMaxRetention</c> upper bound.
    /// </summary>
    [HttpPost]
    public async Task<object?> Add([FromBody] RevokedSidsAddRequest request)
    {
        var validation = ValidateRequest(request);
        if (validation is not null) return validation;

        return await Forward(IdentityEndpoints.RevokedSids, "add",
            new Dictionary<string, object?>
            {
                ["sid"] = request.Sid,
                ["sub"] = request.Sub,
                ["clientId"] = request.ClientId,
                ["expiresAt"] = request.ExpiresAt,
            });
    }

    /// <summary>
    /// Incremental poll. <paramref name="cursor"/> is the <c>NextCursor</c> from the
    /// previous response (ISO-8601 timestamp). Omit on first call \u2014 server returns a
    /// baseline window covering the full retention period.
    /// </summary>
    [HttpGet("since")]
    public async Task<object?> Since([FromQuery("cursor")] string? cursor = null)
    {
        return await Forward(IdentityEndpoints.RevokedSids, "since",
            new Dictionary<string, object?> { ["cursor"] = cursor });
    }
}
