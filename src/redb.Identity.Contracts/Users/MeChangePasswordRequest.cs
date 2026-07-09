using System.ComponentModel.DataAnnotations;

namespace redb.Identity.Contracts.Users;

/// <summary>
/// Self-service password change request for <c>PUT /me/password</c>.
/// Caller identity is taken from the access-token subject — no <c>Id</c> is accepted.
/// </summary>
public class MeChangePasswordRequest
{
    [Required]
    public required string OldPassword { get; set; }

    [Required]
    public required string NewPassword { get; set; }
}
