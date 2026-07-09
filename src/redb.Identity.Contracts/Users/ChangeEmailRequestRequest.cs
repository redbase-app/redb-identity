using System.ComponentModel.DataAnnotations;

namespace redb.Identity.Contracts.Users;

/// <summary>
/// N-4 (Session E, sub-step N4-7): request body for
/// <c>direct-vm://identity-me-change-email-request</c> (and the HTTP facade
/// <c>POST /api/v1/identity/me/change-email/request</c>).
/// <para>
/// Authenticated endpoint: the caller user is derived from the access-token subject.
/// The body carries the address the user wants to switch <em>to</em> plus the BFF's
/// <c>ClientId</c> and the page that will host the confirmation form.
/// </para>
/// </summary>
public class ChangeEmailRequestRequest
{
    /// <summary>
    /// Target e-mail address the user wishes to use going forward. Confirmation link is
    /// dispatched to THIS address; the current address remains the canonical login until
    /// the user proves control of the new one.
    /// </summary>
    [Required]
    public required string NewEmail { get; set; }

    /// <summary>
    /// OAuth client_id of the BFF initiating the change. Used to look up the per-client
    /// confirm-URL whitelist on <c>ApplicationProps.ChangeEmailUris</c>.
    /// </summary>
    [Required]
    public required string ClientId { get; set; }

    /// <summary>
    /// The page that will host the confirmation (e.g.
    /// <c>https://app.example.com/change-email</c>). Must match one of the client's
    /// <c>ChangeEmailUris</c> exactly (string compare); otherwise the request is rejected.
    /// The confirm link is composed as <c>{CallerConfirmUrl}?token={plaintext}&amp;jti={jti}</c>.
    /// </summary>
    [Required]
    public required string CallerConfirmUrl { get; set; }
}

/// <summary>
/// N-4 (Session E, sub-step N4-7): response for the request endpoint. Always
/// <see cref="Success"/> = <c>true</c> when validation passes; failures surface as the
/// standard error envelope.
/// </summary>
public class ChangeEmailRequestResponse
{
    /// <summary><c>true</c> for a successful dispatch attempt.</summary>
    public bool Success { get; set; } = true;
}
