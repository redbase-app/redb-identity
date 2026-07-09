namespace redb.Identity.Contracts.Users;

/// <summary>
/// Self-service profile update request for <c>PUT /me</c>. Caller identity is derived
/// from the authenticated access-token subject; <c>Id</c> is NOT accepted in the body.
/// Admin-only fields (<c>Status</c>, <c>EmailVerified</c>, <c>PhoneNumberVerified</c>)
/// are intentionally absent — a user cannot grant themselves verified flags or toggle
/// their own account status. Changes to those fields require the admin
/// <c>PUT /users/{id}</c> endpoint via <c>identity:manage</c> scope.
/// </summary>
public class MeUpdateProfileRequest
{
    public string? DisplayName { get; set; }
    public string? Email { get; set; }
    public string? PhoneNumber { get; set; }
    public string? GivenName { get; set; }
    public string? FamilyName { get; set; }
    public string? Picture { get; set; }

    /// <summary>OIDC structured address (§5.1.1). Null = no change, empty object = clear.</summary>
    public AddressDto? Address { get; set; }

    /// <summary>Arbitrary custom claims. Null = no change. Keys merged (overwrite).</summary>
    public Dictionary<string, string>? CustomClaims { get; set; }
}
