using System.ComponentModel.DataAnnotations;

namespace redb.Identity.Contracts.Users;

/// <summary>
/// N-4 (Session E, sub-step N4-7): request body for
/// <c>direct-vm://identity-change-email-confirm</c> (and the HTTP facade
/// <c>POST /api/v1/identity/account/change-email/confirm</c>). Anonymous endpoint;
/// rate-limited at the HTTP facade.
/// </summary>
public class ChangeEmailConfirmRequest
{
    /// <summary>Per-issuance identifier captured from the confirm URL <c>?jti=...</c>.</summary>
    [Required]
    public required string Jti { get; set; }

    /// <summary>Plaintext token captured from the confirm URL <c>?token=...</c>.</summary>
    [Required]
    public required string Token { get; set; }
}

/// <summary>
/// N-4 (Session E, sub-step N4-7): response for the confirm endpoint.
/// <para>
/// On failure (bad / expired / consumed token, race detected, new address taken since
/// issue) returns the generic OAuth-style <c>invalid_token</c> error — granular reasons
/// are recorded to audit only.
/// </para>
/// </summary>
public class ChangeEmailConfirmResponse
{
    /// <summary><c>true</c> on success; the user's e-mail is now <c>NewEmail</c> and verified.</summary>
    public bool Success { get; set; }

    /// <summary>OAuth-style error code on failure (always <c>invalid_token</c>).</summary>
    public string? Error { get; set; }

    /// <summary>Human-readable error description (generic).</summary>
    public string? ErrorDescription { get; set; }
}
