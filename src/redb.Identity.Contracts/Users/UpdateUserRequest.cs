using System.ComponentModel.DataAnnotations;

namespace redb.Identity.Contracts.Users;

public class UpdateUserRequest
{
    [Required]
    public long Id { get; set; }

    public string? DisplayName { get; set; }
    public string? Status { get; set; }
    public string? Email { get; set; }
    public bool? EmailVerified { get; set; }
    public string? PhoneNumber { get; set; }
    public bool? PhoneNumberVerified { get; set; }
    public string? GivenName { get; set; }
    public string? FamilyName { get; set; }
    public string? Picture { get; set; }

    /// <summary>OIDC structured address (§5.1.1). Null = no change, empty object = clear.</summary>
    public AddressDto? Address { get; set; }

    /// <summary>Arbitrary claims dictionary. Null = no change. Merged with existing (keys overwrite).</summary>
    public Dictionary<string, string>? CustomClaims { get; set; }
}
