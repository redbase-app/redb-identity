using redb.Identity.Contracts.Routes;
using redb.Identity.Contracts.Users;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// N-4 (Session E, N4-7): self-service strict change-of-e-mail \u2014 initiate side.
/// <c>POST /api/v1/identity/me/change-email/request</c> issues a single-use
/// confirmation token and dispatches an e-mail to the requested <em>new</em> address.
/// The current address remains the canonical login until the user proves control of
/// the new one by clicking the confirm link. Requires Bearer authentication
/// (<c>identity:manage</c> or <c>identity:account</c>); the caller id is derived from
/// the access-token subject. The confirm half of the flow lives on
/// <see cref="AccountChangeEmailController"/> and is anonymous.
/// Feature-gated server-side by <c>RedbIdentityOptions.ChangeEmail.Enabled</c>
/// (default OFF) \u2014 when disabled the route is not registered and the controller
/// surface returns 404 for the in-process route lookup.
/// </summary>
[Route("me/change-email")]
public class MeChangeEmailController : IdentityControllerBase
{
    /// <summary>
    /// Issue a fresh change-of-e-mail token bound to the user's current address and the
    /// requested new address, and deliver the confirmation link via the configured
    /// <c>IEmailNotificationChannel</c>. Returns <c>{ success = true }</c> on success;
    /// failures (missing channel, non-whitelisted callerConfirmUrl, address taken)
    /// surface as standard error envelopes.
    /// </summary>
    [HttpPost("request")]
    public async Task<object?> Request([FromBody] ChangeEmailRequestRequest request)
    {
        return await Forward(IdentityEndpoints.MeChangeEmailRequest, "request", request);
    }
}
