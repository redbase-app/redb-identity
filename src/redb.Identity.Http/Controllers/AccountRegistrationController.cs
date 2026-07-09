using redb.Identity.Contracts.Routes;
using redb.Identity.Contracts.Users;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// N-3 (sub-step N3-7): anonymous self-service account-registration HTTP facade.
/// <list type="bullet">
///   <item><c>POST /api/v1/identity/account/register</c> \u2014 create a new account
///     using a supplied login + e-mail + password. Returns the new user id on success;
///     <c>409 duplicate</c> on collision; <c>400 weak_password</c> / <c>validation_error</c>
///     on input violations; <c>403 registration_disabled</c> when the feature gate is off.
///   </item>
/// </list>
/// Requires NO bearer token \u2014 the route lives on the anonymous prefix
/// <c>/api/v1/identity/account/</c>. Brute-force / enumeration is mitigated by the per-IP
/// throttle processor sitting in front of the direct-vm route (configured in
/// <c>IdentityCoreRouteBuilder</c>).
/// </summary>
[Route("account")]
public class AccountRegistrationController : IdentityControllerBase
{
    /// <summary>
    /// Register a new account. Unlike the password-recovery endpoints this is NOT an
    /// anti-enumeration surface \u2014 duplicate login / e-mail must be surfaced so the
    /// sign-up UI can render an actionable message ("this login is already taken").
    /// </summary>
    [HttpPost("register")]
    public async Task<object?> Register([FromBody] RegisterAccountRequest request)
    {
        return await Forward(IdentityEndpoints.AccountRegister, "register", request);
    }
}
