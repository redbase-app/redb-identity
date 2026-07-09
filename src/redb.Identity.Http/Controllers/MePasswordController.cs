using redb.Identity.Contracts.Users;
using redb.Identity.Contracts.Routes;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// H3 (v1.0 DoD §6): self-service password change at
/// <c>/api/v1/identity/me/password</c>. Caller id is taken from the access-token
/// subject. Enforces the configured password policy and revokes ALL the caller's
/// sessions on success (OWASP Session Management C7) — the user must re-authenticate
/// after a successful change.
/// Auth: Bearer with <c>identity:manage</c> or <c>identity:account</c> scope.
/// </summary>
[Route("me/password")]
public class MePasswordController : IdentityControllerBase
{
    /// <summary>Change the caller's own password. Returns <c>{ success, sessionsRevoked }</c>.</summary>
    [HttpPut]
    public async Task<object?> Change([FromBody] MeChangePasswordRequest request)
    {
        return await Forward(IdentityEndpoints.MePassword, "change", request);
    }
}
