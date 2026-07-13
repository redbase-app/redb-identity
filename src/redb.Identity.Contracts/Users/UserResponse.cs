namespace redb.Identity.Contracts.Users;

public class UserResponse
{
    public long Id { get; set; }

    /// <summary>
    /// Public OIDC <c>sub</c> claim — stable per-user GUID emitted in every
    /// id_token / access_token issued for this user. Distinct from
    /// <see cref="Id"/> (the internal bigint primary key used by admin API
    /// paths). Null when the user has no OIDC profile object yet (e.g.
    /// freshly imported via SCIM before first sign-in initialises one).
    /// </summary>
    public Guid? SubjectGuid { get; set; }

    public string? Login { get; set; }
    public string? DisplayName { get; set; }
    public string? Status { get; set; }
    public string? Email { get; set; }
    public bool EmailVerified { get; set; }
    public string? PhoneNumber { get; set; }
    public bool PhoneNumberVerified { get; set; }
    // OIDC Core §5.1 `profile` claims (the set userinfo returns for scope=profile).
    public string? GivenName { get; set; }
    public string? FamilyName { get; set; }
    public string? MiddleName { get; set; }
    public string? Nickname { get; set; }
    public string? PreferredUsername { get; set; }
    public string? Profile { get; set; }
    public string? Picture { get; set; }
    public string? Website { get; set; }
    public string? Gender { get; set; }
    public string? Birthdate { get; set; }
    public string? ZoneInfo { get; set; }
    public string? Locale { get; set; }
    public AddressDto? Address { get; set; }
    public Dictionary<string, string>? CustomClaims { get; set; }

    /// <summary>Federation identities keyed by provider ID. Null if local-only user.</summary>
    public Dictionary<string, ExternalIdentityDto>? ExternalIdentities { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ModifiedAt { get; set; }
}
