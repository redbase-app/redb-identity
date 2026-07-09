using redb.Identity.Contracts.Routes;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// REST management API for MFA configuration.
/// Forwards to <c>direct-vm://identity-manage-mfa</c> route.
/// </summary>
[Route("mfa")]
public class MfaController : IdentityControllerBase
{
    [HttpGet("status/{userId}")]
    public async Task<object?> GetStatus([FromRoute("userId")] string userId)
    {
        return await Forward(IdentityEndpoints.MfaManage, "status",
            new Dictionary<string, object> { ["userId"] = ParseLong(userId) });
    }

    [HttpPost("totp/setup")]
    public async Task<object?> SetupTotp([FromBody] MfaSetupRequest request)
    {
        if (ValidateRequest(request) is { } problem) return problem;
        return await Forward(IdentityEndpoints.MfaManage, "setup",
            new Dictionary<string, object?>
            {
                ["userId"] = request.UserId,
                ["method"] = "totp",
                ["username"] = request.Username
            });
    }

    [HttpPost("totp/confirm")]
    public async Task<object?> ConfirmTotp([FromBody] MfaConfirmRequest request)
    {
        if (ValidateRequest(request) is { } problem) return problem;
        return await Forward(IdentityEndpoints.MfaManage, "confirm",
            new Dictionary<string, object?>
            {
                ["userId"] = request.UserId,
                ["method"] = "totp",
                ["code"] = request.Code
            });
    }

    [HttpDelete("totp/{userId}")]
    public async Task<object?> DisableTotp([FromRoute("userId")] string userId)
    {
        return await Forward(IdentityEndpoints.MfaManage, "disable",
            new Dictionary<string, object?>
            {
                ["userId"] = ParseLong(userId),
                ["method"] = "totp"
            });
    }

    [HttpPost("recovery-codes/regenerate")]
    public async Task<object?> RegenerateRecoveryCodes([FromBody] MfaUserIdRequest request)
    {
        if (ValidateRequest(request) is { } problem) return problem;
        return await Forward(IdentityEndpoints.MfaManage, "regenerate-recovery",
            new Dictionary<string, object?> { ["userId"] = request.UserId });
    }

    // ── SMS OTP ──────────────────────────────────────────────────────────────

    [HttpPost("sms/setup")]
    public async Task<object?> SetupSms([FromBody] MfaOtpSetupRequest request)
    {
        if (ValidateRequest(request) is { } problem) return problem;
        return await Forward(IdentityEndpoints.MfaManage, "setup",
            new Dictionary<string, object?>
            {
                ["userId"] = request.UserId,
                ["method"] = "sms",
                ["username"] = request.Username,
                ["destination"] = request.Destination
            });
    }

    [HttpPost("sms/confirm")]
    public async Task<object?> ConfirmSms([FromBody] MfaOtpConfirmRequest request)
    {
        if (ValidateRequest(request) is { } problem) return problem;
        return await Forward(IdentityEndpoints.MfaManage, "confirm",
            new Dictionary<string, object?>
            {
                ["userId"] = request.UserId,
                ["method"] = "sms",
                ["code"] = request.Code,
                ["mfa_state"] = request.MfaState
            });
    }

    [HttpDelete("sms/{userId}")]
    public async Task<object?> DisableSms([FromRoute("userId")] string userId)
    {
        return await Forward(IdentityEndpoints.MfaManage, "disable",
            new Dictionary<string, object?>
            {
                ["userId"] = ParseLong(userId),
                ["method"] = "sms"
            });
    }

    // ── Email OTP ────────────────────────────────────────────────────────────

    [HttpPost("email/setup")]
    public async Task<object?> SetupEmail([FromBody] MfaOtpSetupRequest request)
    {
        if (ValidateRequest(request) is { } problem) return problem;
        return await Forward(IdentityEndpoints.MfaManage, "setup",
            new Dictionary<string, object?>
            {
                ["userId"] = request.UserId,
                ["method"] = "email",
                ["username"] = request.Username,
                ["destination"] = request.Destination
            });
    }

    [HttpPost("email/confirm")]
    public async Task<object?> ConfirmEmail([FromBody] MfaOtpConfirmRequest request)
    {
        if (ValidateRequest(request) is { } problem) return problem;
        return await Forward(IdentityEndpoints.MfaManage, "confirm",
            new Dictionary<string, object?>
            {
                ["userId"] = request.UserId,
                ["method"] = "email",
                ["code"] = request.Code,
                ["mfa_state"] = request.MfaState
            });
    }

    [HttpDelete("email/{userId}")]
    public async Task<object?> DisableEmail([FromRoute("userId")] string userId)
    {
        return await Forward(IdentityEndpoints.MfaManage, "disable",
            new Dictionary<string, object?>
            {
                ["userId"] = ParseLong(userId),
                ["method"] = "email"
            });
    }

    private static long ParseLong(string value) =>
        long.TryParse(value, out var id) ? id : 0;
}
