using System.ComponentModel.DataAnnotations;

namespace redb.Identity.Contracts.Users;

/// <summary>
/// N-3 (sub-step N3-6/N3-7): request body for self-service account registration
/// (<c>direct-vm://identity-account-register</c> and the HTTP facade
/// <c>POST /api/v1/identity/account/register</c>).
/// <para>
/// Endpoint is anonymous and gated by <c>RedbIdentityOptions.Registration.Enabled</c>;
/// when the master switch is off the route is not built and the facade returns 404.
/// Rate-limiting is layered upstream identically to <see cref="PasswordForgotRequest"/>.
/// </para>
/// </summary>
public class RegisterAccountRequest
{
    /// <summary>
    /// Desired login. Must be unique. Same validation as the admin <c>CreateUser</c> path
    /// (length, allowed characters). Stored as <c>_users.login</c>.
    /// </summary>
    [Required]
    public required string Login { get; set; }

    /// <summary>
    /// Initial password. Validated against the full server-side password policy
    /// (length + composition + history + breach) before storage.
    /// </summary>
    [Required]
    public required string Password { get; set; }

    /// <summary>
    /// Required e-mail address. Unlike the admin path, anonymous registration cannot
    /// leave the e-mail empty — it is the only mechanism for password recovery /
    /// e-mail verification later, and it is the natural duplicate-account guard.
    /// </summary>
    [Required]
    public required string Email { get; set; }

    /// <summary>Optional display name. Defaults to the login when omitted.</summary>
    public string? DisplayName { get; set; }
}

/// <summary>
/// N-3: response for <see cref="RegisterAccountRequest"/>. The processor returns
/// <see cref="Success"/> = <c>true</c> together with the new user id on success, and a
/// structured error code on failure (validation / duplicate / disabled). Unlike the
/// password-recovery endpoint this is NOT an anti-enumeration surface — duplicate
/// login / e-mail must be visible so the UI can render an actionable message.
/// </summary>
public class RegisterAccountResponse
{
    /// <summary><c>true</c> when the account was created and persisted.</summary>
    public bool Success { get; set; }

    /// <summary>Identifier of the newly created user. Populated only when <see cref="Success"/> = <c>true</c>.</summary>
    public long? UserId { get; set; }

    /// <summary>Echo of <c>Login</c> on success — useful for the BFF auto-sign-in step.</summary>
    public string? Login { get; set; }

    /// <summary>
    /// Stable machine-readable error code on failure: <c>validation_error</c> /
    /// <c>duplicate</c> / <c>registration_disabled</c> / <c>weak_password</c>.
    /// </summary>
    public string? Error { get; set; }

    /// <summary>Human-readable description for the failing case. Safe to surface to the user.</summary>
    public string? ErrorDescription { get; set; }
}
