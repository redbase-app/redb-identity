using System.ComponentModel.DataAnnotations;

namespace redb.Identity.Contracts.Consents;

/// <summary>
/// Self-service consent revoke request for <c>DELETE /me/consents/{clientId}</c>.
/// Targets ALL consent grants for the given client_id owned by the caller.
/// </summary>
public class MeRevokeConsentRequest
{
    [Required]
    public required string ClientId { get; set; }
}
