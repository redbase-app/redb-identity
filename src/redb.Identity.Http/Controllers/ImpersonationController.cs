using redb.Identity.Contracts.Routes;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// N7-3 — admin impersonation overlay. Forwards to <c>direct-vm://identity-manage-impersonation</c>.
/// <para>
/// Routes are mounted under <c>/admin/impersonate</c>; the granular scope guard
/// (see <c>GranularScopeGuardProcessor</c>) requires the <c>identity:impersonate</c>
/// scope (or master <c>identity:manage</c>) on the caller's bearer token.
/// </para>
/// <para>
/// This endpoint does NOT mint a token. It validates the target user exists, then writes
/// an audit event recording the admin's <c>sub</c> and the impersonated user id. The BFF
/// maintains the actual impersonation state (session cookie) and routes subsequent admin
/// calls accordingly.
/// </para>
/// </summary>
[Route("admin/impersonate")]
public class ImpersonationController : IdentityControllerBase
{
    /// <summary>
    /// Start an impersonation session. <c>userId</c> in the path is the target user id;
    /// optional <c>reason</c> in the body is persisted in the audit event payload.
    /// </summary>
    [HttpPost("start/{userId}")]
    public async Task<object?> Start([FromRoute("userId")] string userId, [FromBody] StartImpersonationRequest? body = null)
    {
        if (!long.TryParse(userId, out var id) || id <= 0)
        {
            return new
            {
                error = "invalid_request",
                error_description = "userId must be a positive integer"
            };
        }

        return await Forward(IdentityEndpoints.ManageImpersonation, "start",
            new Dictionary<string, object?>
            {
                ["userId"] = id,
                ["reason"] = body?.Reason
            });
    }

    /// <summary>
    /// Stop an active impersonation session. <c>userId</c> in the path is the target user id
    /// the admin was impersonating (used only for the audit record).
    /// </summary>
    [HttpPost("stop/{userId}")]
    public async Task<object?> Stop([FromRoute("userId")] string userId)
    {
        if (!long.TryParse(userId, out var id) || id <= 0)
        {
            return new
            {
                error = "invalid_request",
                error_description = "userId must be a positive integer"
            };
        }

        return await Forward(IdentityEndpoints.ManageImpersonation, "stop",
            new Dictionary<string, object?> { ["userId"] = id });
    }
}

/// <summary>Optional body for <c>POST /admin/impersonate/start/{userId}</c>.</summary>
public sealed class StartImpersonationRequest
{
    /// <summary>Free-form human-readable reason (e.g. "Customer ticket #12345"). Persisted in audit log.</summary>
    public string? Reason { get; set; }
}
