using redb.Identity.Contracts.Routes;
using redb.Identity.Contracts.Users;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// N-4 (Session C): anonymous password-recovery HTTP facade.
/// <list type="bullet">
///   <item><c>POST /api/v1/identity/password/forgot</c> — initiate recovery.
///     Anti-enumeration: always 200 success, even when the e-mail does not match a user
///     or the <c>callerResetUrl</c> is not whitelisted on the client.</item>
///   <item><c>POST /api/v1/identity/password/reset</c> — complete recovery by verifying
///     the single-use token and setting the new password (revokes all sessions).</item>
/// </list>
/// Both endpoints require NO bearer token — they are reachable by any unauthenticated
/// browser / SDK caller. Brute-force enumeration is mitigated by the per-IP throttle
/// processor sitting in front of both direct-vm routes (configured in
/// <c>IdentityCoreRouteBuilder</c>).
/// </summary>
[Route("password")]
public class PasswordRecoveryController : IdentityControllerBase
{
    /// <summary>
    /// Initiate password recovery for the supplied e-mail. Always returns
    /// <c>{ success = true }</c> regardless of outcome to prevent account enumeration —
    /// the actual delivery decision is made server-side and recorded in the audit log.
    /// </summary>
    [HttpPost("forgot")]
    public async Task<object?> Forgot([FromBody] PasswordForgotRequest request)
    {
        return await Forward(IdentityEndpoints.PasswordForgot, "forgot", request);
    }

    /// <summary>
    /// Complete password recovery: verify + atomically consume the reset token, validate
    /// the new password against the policy, persist it, and revoke every active session.
    /// Failures return generic <c>invalid_token</c> regardless of the specific cause
    /// (bad / expired / consumed token, unknown user) — granular reason lives only in
    /// audit logs to deny attackers useful guessing signal.
    /// </summary>
    [HttpPost("reset")]
    public async Task<object?> Reset([FromBody] PasswordResetRequest request)
    {
        return await Forward(IdentityEndpoints.PasswordReset, "reset", request);
    }
}
