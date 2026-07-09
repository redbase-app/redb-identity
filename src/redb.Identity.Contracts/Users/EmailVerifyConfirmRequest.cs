using System.ComponentModel.DataAnnotations;

namespace redb.Identity.Contracts.Users;

/// <summary>
/// N-4 (Session C, sub-step N4-6): request body for
/// <c>direct-vm://identity-email-verify-confirm</c> (and the HTTP facade
/// <c>POST /api/v1/identity/account/verify-email/confirm</c>).
/// Anonymous endpoint; rate-limited at the HTTP facade.
/// </summary>
public class EmailVerifyConfirmRequest
{
    /// <summary>Per-issuance identifier captured from the verify URL <c>?jti=...</c>.</summary>
    [Required]
    public required string Jti { get; set; }

    /// <summary>Plaintext token captured from the verify URL <c>?token=...</c>.</summary>
    [Required]
    public required string Token { get; set; }
}

/// <summary>
/// N-4 (Session C, sub-step N4-6): response for the confirm endpoint.
/// <para>
/// On failure (bad / expired / consumed token, or e-mail changed since issue) returns
/// the generic OAuth-style <c>invalid_token</c> error — granular reasons are recorded
/// to audit only, never returned to anonymous callers (defence against enumeration of
/// jti values).
/// </para>
/// </summary>
public class EmailVerifyConfirmResponse
{
    /// <summary><c>true</c> on success; the user's <c>EmailVerified</c> flag is now <c>true</c>.</summary>
    public bool Success { get; set; }

    /// <summary>OAuth-style error code on failure (always <c>invalid_token</c>).</summary>
    public string? Error { get; set; }

    /// <summary>Human-readable error description (generic).</summary>
    public string? ErrorDescription { get; set; }
}
