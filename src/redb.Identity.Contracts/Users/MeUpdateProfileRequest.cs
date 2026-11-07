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

    // OIDC Core §5.1 `profile` claims. The whole set is settable here so userinfo can return it —
    // the conformance suite checks userinfo against exactly this list for scope=profile.
    public string? GivenName { get; set; }
    public string? FamilyName { get; set; }
    public string? MiddleName { get; set; }
    public string? Nickname { get; set; }
    /// <summary>Shorthand name for the RP's UI. Falls back to the login when unset.</summary>
    public string? PreferredUsername { get; set; }
    /// <summary>URL of the user's profile page (OIDC: profile).</summary>
    public string? Profile { get; set; }
    public string? Picture { get; set; }
    public string? Website { get; set; }
    public string? Gender { get; set; }
    /// <summary>ISO 8601 <c>YYYY-MM-DD</c> (a bare year is allowed).</summary>
    public string? Birthdate { get; set; }
    /// <summary>IANA time-zone name, e.g. "Europe/Moscow".</summary>
    public string? ZoneInfo { get; set; }
    /// <summary>BCP 47 language tag, e.g. "ru-RU".</summary>
    public string? Locale { get; set; }

    /// <summary>OIDC structured address (§5.1.1). Null = no change, empty object = clear.</summary>
    public AddressDto? Address { get; set; }

    /// <summary>Arbitrary custom claims. Null = no change. Keys merged (overwrite).</summary>
    public Dictionary<string, string>? CustomClaims { get; set; }
}
