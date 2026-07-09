using System.ComponentModel.DataAnnotations;

namespace redb.Identity.Contracts.Users;

/// <summary>
/// N-4 (Session C, sub-step N4-6): request body for
/// <c>direct-vm://identity-me-email-verify-send</c> (and the HTTP facade
/// <c>POST /api/v1/identity/me/verify-email/send</c>).
/// <para>
/// Authenticated endpoint: the user + target e-mail are taken from the access-token
/// subject, so a caller cannot trigger a verify e-mail to someone else's inbox.
/// </para>
/// </summary>
public class EmailVerifySendRequest
{
    /// <summary>
    /// OAuth client_id of the BFF initiating the verification. Used to look up the
    /// per-client verify-URL whitelist on <c>ApplicationProps.EmailVerifyUris</c>.
    /// </summary>
    [Required]
    public required string ClientId { get; set; }

    /// <summary>
    /// The page that will host the verify-confirmation (e.g.
    /// <c>https://app.example.com/verify-email</c>). Must match one of the client's
    /// <c>EmailVerifyUris</c> exactly (string compare); otherwise the request is
    /// silently dropped (success returned for anti-enumeration symmetry with forgot).
    /// The verify link e-mailed to the user is composed as
    /// <c>{CallerVerifyUrl}?token={plaintext}&amp;jti={jti}</c>.
    /// </summary>
    [Required]
    public required string CallerVerifyUrl { get; set; }
}

/// <summary>
/// N-4 (Session C, sub-step N4-6): generic response for the send endpoint. Always
/// <see cref="Success"/> = <c>true</c> when authentication passes. Reserved for future
/// fatal-error signaling (e.g. SMTP down).
/// </summary>
public class EmailVerifySendResponse
{
    /// <summary>Always <c>true</c> for a successful dispatch attempt.</summary>
    public bool Success { get; set; } = true;
}
