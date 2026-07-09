using redb.Identity.Contracts.Routes;
using redb.Identity.Contracts.Users;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// N-4 (Session C, N4-6): anonymous e-mail-verification — confirm side.
/// <c>POST /api/v1/identity/account/verify-email/confirm</c> verifies + atomically
/// consumes a verification token (issued by <c>POST /me/verify-email/send</c>) and
/// flips <c>UserProps.EmailVerified=true</c> when the bound e-mail still matches the
/// user's current address (double-change race protection — a stale token never
/// vouches for a freshly changed e-mail). Failures return generic
/// <c>invalid_token</c> regardless of cause; granular reason is recorded only in
/// audit logs to deny attackers a guessing signal. The route lives under
/// <c>/api/v1/identity/account/</c> so it can be whitelisted alongside
/// <c>/api/v1/identity/password/</c> without exposing other <c>me/*</c> endpoints
/// anonymously.
/// </summary>
[Route("account/verify-email")]
public class AccountEmailVerifyController : IdentityControllerBase
{
    /// <summary>Verify and consume an e-mail verification token. Single-use.</summary>
    [HttpPost("confirm")]
    public async Task<object?> Confirm([FromBody] EmailVerifyConfirmRequest request)
    {
        return await Forward(IdentityEndpoints.EmailVerifyConfirm, "confirm", request);
    }
}
