using System.ComponentModel.DataAnnotations;

namespace redb.Identity.Contracts.Consents;

/// <summary>
/// Self-service consent grant request for <c>POST /me/consents</c>. The caller's
/// user id is taken from the access-token subject — it is never accepted from the
/// request body. <see cref="Scopes"/> must be the exact set the user is approving
/// for the given client; the underlying <c>ConsentService.GrantAsync</c> performs a
/// union with any pre-existing valid permanent grant.
/// </summary>
public sealed class GrantMyConsentRequest
{
    /// <summary>OAuth client_id of the application receiving consent.</summary>
    [Required]
    public required string ClientId { get; set; }

    /// <summary>Scope identifiers (e.g. <c>openid</c>, <c>profile</c>, <c>email</c>).</summary>
    [Required]
    public required string[] Scopes { get; set; }
}
