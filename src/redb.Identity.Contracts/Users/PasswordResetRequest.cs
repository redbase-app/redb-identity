using System.ComponentModel.DataAnnotations;

namespace redb.Identity.Contracts.Users;

/// <summary>
/// N-4 (Session C): request body for <c>direct-vm://identity-password-reset</c>
/// (and the HTTP facade <c>POST /api/v1/identity/password/reset</c>).
/// <para>
/// Carries the (<see cref="Jti"/>, <see cref="Token"/>) pair extracted from the reset link
/// plus the new password. The processor verifies + atomically consumes the token via
/// <c>IPasswordResetTokenStore</c>, validates the new password against the policy, sets it
/// via <c>IUserProvider.SetPasswordAsync</c>, and revokes every active session for the user.
/// </para>
/// </summary>
public class PasswordResetRequest
{
    /// <summary>Per-issuance identifier emitted by <c>IPasswordResetTokenStore.IssueAsync</c>.</summary>
    [Required]
    public required string Jti { get; set; }

    /// <summary>Plaintext reset token (32-byte base64url) from the reset link.</summary>
    [Required]
    public required string Token { get; set; }

    /// <summary>New password. Validated against the configured password policy before persistence.</summary>
    [Required]
    public required string NewPassword { get; set; }
}

/// <summary>
/// N-4 (Session C): response for the reset endpoint. On success, <see cref="Success"/> is
/// <c>true</c> and <see cref="SessionsRevoked"/> reports how many active sessions were
/// invalidated by the change. On failure (bad / expired / consumed token, policy
/// violation), <see cref="Success"/> is <c>false</c> and <see cref="Error"/> carries a
/// short machine-readable code — error descriptions are intentionally generic to deny
/// guessing attempts useful signal.
/// </summary>
public class PasswordResetResponse
{
    public bool Success { get; set; }
    public string? Error { get; set; }
    public string? ErrorDescription { get; set; }
    public int SessionsRevoked { get; set; }
}
