namespace redb.Identity.Contracts.Users;

/// <summary>
/// OIDC structured address claim (§5.1.1).
/// Used in user management API requests/responses.
/// </summary>
public class AddressDto
{
    public string? StreetAddress { get; set; }
    public string? Locality { get; set; }
    public string? Region { get; set; }
    public string? PostalCode { get; set; }
    public string? Country { get; set; }
    public string? Formatted { get; set; }
}
