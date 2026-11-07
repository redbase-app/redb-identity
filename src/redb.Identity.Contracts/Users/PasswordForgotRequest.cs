using System.ComponentModel.DataAnnotations;

namespace redb.Identity.Contracts.Users;

/// <summary>
/// N-4 (Session C): request body for <c>direct-vm://identity-password-forgot</c>
/// (and the HTTP facade <c>POST /api/v1/identity/password/forgot</c>).
/// <para>
/// Always returns success to the caller regardless of whether <see cref="Email"/> matches
/// an existing user — this is the anti-enumeration contract. The processor only sends an
/// e-mail when the (email, clientId, callerResetUrl) tuple resolves to a real user and the
/// reset URL is in the client's <c>ApplicationProps.PasswordResetUris</c> whitelist.
/// </para>
/// </summary>
public class PasswordForgotRequest
{
    /// <summary>User-supplied e-mail. Looked up against <c>UserSearchCriteria.EmailExact</c>.</summary>
    [Required]
    public required string Email { get; set; }

    /// <summary>
    /// OAuth client_id of the BFF initiating the reset. Used to look up the per-client
    /// password-reset URL whitelist on <c>ApplicationProps.PasswordResetUris</c>.
    /// </summary>
    [Required]
    public required string ClientId { get; set; }

    /// <summary>
    /// The page that will host the reset form (e.g. <c>https://app.example.com/reset-password</c>).
    /// Must match one of the client's <c>PasswordResetUris</c> exactly (string compare); if
    /// not, the request is silently dropped (anti-enumeration: still returns success).
    /// The reset link e-mailed to the user is composed as
    /// <c>{CallerResetUrl}?token={plaintext}&amp;jti={jti}</c>.
    /// </summary>
    [Required]
    public required string CallerResetUrl { get; set; }
}

/// <summary>
/// N-4 (Session C): generic response for the forgot endpoint. Always
/// <see cref="Success"/> = <c>true</c> to prevent account enumeration via the response
/// body. The HTTP facade should also normalize timing to a constant ceiling.
/// </summary>
public class PasswordForgotResponse
{
    /// <summary>Always <c>true</c>. Reserved for future fatal-error signaling (e.g. SMTP down).</summary>
    public bool Success { get; set; } = true;
}
