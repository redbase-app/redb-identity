using redb.Identity.Contracts.Routes;
using redb.Identity.Contracts.Users;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// N-4 (Session C, N4-6): self-service e-mail verification — initiate side.
/// <c>POST /api/v1/identity/me/verify-email/send</c> issues a single-use
/// verification token and dispatches an e-mail to the caller's current address.
/// Requires Bearer authentication (<c>identity:manage</c> or <c>identity:account</c>);
/// the caller id is derived from the access-token subject. The confirm half of the
/// flow lives on <see cref="AccountEmailVerifyController"/> and is anonymous.
/// Feature-gated server-side by <c>RedbIdentityOptions.EmailVerification.Enabled</c>
/// (default OFF) — when disabled the route is not registered and the controller
/// surface returns 404 for the in-process route lookup.
/// </summary>
[Route("me/verify-email")]
public class MeEmailVerifyController : IdentityControllerBase
{
    /// <summary>
    /// Issue a fresh verification token for the caller's e-mail and deliver it via
    /// the configured <c>IEmailNotificationChannel</c>. Always returns
    /// <c>{ success = true }</c> on success; failures (missing channel, missing e-mail,
    /// non-whitelisted callerVerifyUrl) surface as standard error envelopes.
    /// </summary>
    [HttpPost("send")]
    public async Task<object?> Send([FromBody] EmailVerifySendRequest request)
    {
        return await Forward(IdentityEndpoints.MeEmailVerifySend, "send", request);
    }
}
