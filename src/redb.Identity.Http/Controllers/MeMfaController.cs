using redb.Identity.Contracts.Routes;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// H3 (v1.0 DoD §6): self-service MFA management at
/// <c>/api/v1/identity/me/mfa/*</c>. Mirrors the admin <c>/mfa/*</c> surface but
/// always derives the user id from the access-token subject — under no circumstances
/// may a caller setup, confirm, disable, or regenerate codes for someone else.
/// Auth: Bearer with <c>identity:manage</c> or <c>identity:account</c> scope.
/// </summary>
[Route("me/mfa")]
public class MeMfaController : IdentityControllerBase
{
    /// <summary>Return MFA enrollment status for the caller.</summary>
    [HttpGet]
    public async Task<object?> Status()
    {
        return await Forward(IdentityEndpoints.MeMfa, "status",
            new Dictionary<string, object?>());
    }

    /// <summary>
    /// Begin enrolment of an additional MFA method. Body is forwarded as-is
    /// (<c>method</c>, <c>destination</c>, …); the user id is supplied by the
    /// processor from the token subject and overrides any value sent by the client.
    /// </summary>
    [HttpPost("setup")]
    public async Task<object?> Setup([FromBody] Dictionary<string, object?> body)
    {
        return await Forward(IdentityEndpoints.MeMfa, "setup", body);
    }

    /// <summary>Confirm a pending MFA enrolment with the OTP code returned to the user.</summary>
    [HttpPost("confirm")]
    public async Task<object?> Confirm([FromBody] Dictionary<string, object?> body)
    {
        return await Forward(IdentityEndpoints.MeMfa, "confirm", body);
    }

    /// <summary>Disable a single MFA method registered to the caller.</summary>
    [HttpDelete("{method}")]
    public async Task<object?> Disable([FromRoute("method")] string method)
    {
        return await Forward(IdentityEndpoints.MeMfa, "disable",
            new Dictionary<string, object?> { ["method"] = method });
    }

    /// <summary>Regenerate the caller's recovery codes (invalidates all previous codes).</summary>
    [HttpPost("recovery-codes")]
    public async Task<object?> RegenerateRecoveryCodes()
    {
        return await Forward(IdentityEndpoints.MeMfa, "regenerate-recovery",
            new Dictionary<string, object?>());
    }

    /// <summary>
    /// MFA backup-codes download UX — regenerates the caller's recovery codes and returns
    /// them as a <c>text/plain</c> attachment with <c>Content-Disposition: attachment;
    /// filename=redb-recovery-codes.txt</c>. Mirrors GitHub / Google / Auth0 behaviour:
    /// downloading is destructive (atomically invalidates the prior batch) since recovery
    /// codes are stored only as salted hashes server-side and have no other moment of
    /// existing in plaintext.
    /// </summary>
    [HttpGet("recovery-codes/download")]
    public async Task<object?> DownloadRecoveryCodes()
    {
        return await Forward(IdentityEndpoints.MeMfa, "download-recovery",
            new Dictionary<string, object?>());
    }
}
