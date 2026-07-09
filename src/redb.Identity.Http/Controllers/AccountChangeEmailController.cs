using redb.Identity.Contracts.Routes;
using redb.Identity.Contracts.Users;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// N-4 (Session E, N4-7): anonymous change-of-e-mail \u2014 confirm side.
/// <c>POST /api/v1/identity/account/change-email/confirm</c> verifies + atomically
/// consumes a confirmation token (issued by <c>POST /me/change-email/request</c>) and
/// swaps the user's e-mail to the new address while flipping
/// <c>UserProps.EmailVerified=true</c>. The swap is only applied when the user's
/// current address still matches the snapshot captured at issue time \u2014 a race
/// against another mutation path aborts the commit with a generic
/// <c>invalid_token</c> response.
/// All failures return <c>invalid_token</c> regardless of cause; granular reason is
/// recorded only in audit logs. The route lives under
/// <c>/api/v1/identity/account/</c> so it can be whitelisted alongside
/// <c>/api/v1/identity/password/</c> without exposing other <c>me/*</c> endpoints
/// anonymously.
/// </summary>
[Route("account/change-email")]
public class AccountChangeEmailController : IdentityControllerBase
{
    /// <summary>Verify and consume a change-of-e-mail token. Single-use.</summary>
    [HttpPost("confirm")]
    public async Task<object?> Confirm([FromBody] ChangeEmailConfirmRequest request)
    {
        return await Forward(IdentityEndpoints.ChangeEmailConfirm, "confirm", request);
    }
}
