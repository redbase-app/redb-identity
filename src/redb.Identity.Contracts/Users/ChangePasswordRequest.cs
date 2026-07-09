using System.ComponentModel.DataAnnotations;

namespace redb.Identity.Contracts.Users;

public class ChangePasswordRequest
{
    [Required]
    public long Id { get; set; }

    [Required]
    public required string OldPassword { get; set; }

    [Required]
    public required string NewPassword { get; set; }
}
