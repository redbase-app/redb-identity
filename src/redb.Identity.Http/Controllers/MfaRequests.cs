using System.ComponentModel.DataAnnotations;

namespace redb.Identity.Http.Controllers;

public class MfaSetupRequest
{
    [Range(1, long.MaxValue, ErrorMessage = "userId must be a positive integer.")]
    public long UserId { get; set; }
    public string? Username { get; set; }
}

public class MfaConfirmRequest
{
    [Range(1, long.MaxValue, ErrorMessage = "userId must be a positive integer.")]
    public long UserId { get; set; }

    [Required(AllowEmptyStrings = false, ErrorMessage = "code is required.")]
    public string Code { get; set; } = "";
}

public class MfaUserIdRequest
{
    [Range(1, long.MaxValue, ErrorMessage = "userId must be a positive integer.")]
    public long UserId { get; set; }
}

/// <summary>SMS / Email setup request: caller supplies destination (phone or email).</summary>
public class MfaOtpSetupRequest
{
    [Range(1, long.MaxValue, ErrorMessage = "userId must be a positive integer.")]
    public long UserId { get; set; }
    public string? Username { get; set; }

    [Required(AllowEmptyStrings = false, ErrorMessage = "destination is required.")]
    public string Destination { get; set; } = "";
}

/// <summary>
/// Confirm SMS/Email setup. Caller must supply both the user-entered <c>Code</c> and the
/// encrypted <c>MfaState</c> returned by the prior /mfa/{method}/challenge call.
/// </summary>
public class MfaOtpConfirmRequest
{
    [Range(1, long.MaxValue, ErrorMessage = "userId must be a positive integer.")]
    public long UserId { get; set; }

    [Required(AllowEmptyStrings = false, ErrorMessage = "code is required.")]
    public string Code { get; set; } = "";

    [Required(AllowEmptyStrings = false, ErrorMessage = "mfaState is required.")]
    public string MfaState { get; set; } = "";
}
