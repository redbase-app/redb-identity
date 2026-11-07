using System.ComponentModel.DataAnnotations;

namespace redb.Identity.Contracts.Users;

public class CreateUserRequest
{
    [Required]
    public required string Login { get; set; }

    [Required]
    public required string Password { get; set; }

    public string? DisplayName { get; set; }

    public string? Email { get; set; }
    public string? PhoneNumber { get; set; }
    public string? GivenName { get; set; }
    public string? FamilyName { get; set; }
    public string? Picture { get; set; }

    /// <summary>
    /// S2 — optional custom claims dictionary applied at create time so an
    /// admin can satisfy required <c>ClaimDefinitionProps</c> in a single
    /// POST. Validated against the global schema; required claims without a
    /// default and not supplied here cause 400 validation_error.
    /// </summary>
    public Dictionary<string, string>? CustomClaims { get; set; }
}
