using redb.Identity.Contracts.Users;
using redb.Identity.Contracts.Routes;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// H3 (v1.0 DoD §6): self-service profile endpoint at
/// <c>/api/v1/identity/me</c>. Caller identity is taken from the access-token subject;
/// admin-only fields (<c>Status</c>, <c>EmailVerified</c>, <c>PhoneNumberVerified</c>)
/// are intentionally absent from <see cref="MeUpdateProfileRequest"/> — users cannot
/// flip their own verified flags or self-promote the account status.
/// Auth: Bearer with <c>identity:manage</c> or <c>identity:account</c> scope.
/// </summary>
[Route("me")]
public class MeController : IdentityControllerBase
{
    /// <summary>Return the caller's own profile.</summary>
    [HttpGet]
    public async Task<object?> Read()
    {
        return await Forward(IdentityEndpoints.MeProfile, "read", null);
    }

    /// <summary>
    /// Patch the caller's own profile (display name, email, phone, OIDC extension
    /// claims). Verified flags and account status are not exposed and remain
    /// admin-only via <c>UserManagementProcessor</c>.
    /// </summary>
    [HttpPut]
    public async Task<object?> Update([FromBody] MeUpdateProfileRequest request)
    {
        return await Forward(IdentityEndpoints.MeProfile, "update", request);
    }

    /// <summary>
    /// Self-service account deletion. Cascade-revokes every session (and the OpenIddict
    /// authorizations + access/refresh tokens linked to them) and soft-deletes the
    /// caller's user row + OIDC props. Login STAYS occupied so re-registration with
    /// the same login is blocked while the soft-deleted row exists (matches the
    /// <c>protect_system_users</c> trigger contract that <c>_login</c> is immutable).
    /// Idempotent — repeat calls return <c>{ success: true, alreadyAbsent: true }</c>.
    /// </summary>
    [HttpDelete]
    public async Task<object?> Delete()
    {
        return await Forward(IdentityEndpoints.MeProfile, "delete", null);
    }
}
