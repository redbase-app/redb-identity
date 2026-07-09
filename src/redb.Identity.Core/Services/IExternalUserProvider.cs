namespace redb.Identity.Core.Services;

/// <summary>
/// SPI for pluggable external authentication providers (LDAP, SAML, OIDC federation, etc.).
/// Implementations are registered in DI and tried in <see cref="Priority"/> order by
/// <see cref="LoginService"/> before falling back to the local <c>_users</c> password check.
/// </summary>
public interface IExternalUserProvider
{
    /// <summary>Provider identifier, e.g. "ldap", "oidc:google", "saml:corp".</summary>
    string ProviderName { get; }

    /// <summary>Lower value = tried first. Default providers should use 100+.</summary>
    int Priority { get; }

    /// <summary>
    /// Attempts to authenticate <paramref name="username"/> / <paramref name="password"/>
    /// against the external system.
    /// Returns <c>null</c> if this provider does not handle the given user (next provider is tried).
    /// Returns a result with <see cref="ExternalAuthResult.Succeeded"/> = false for explicit auth failure
    /// (e.g. valid LDAP user but wrong password — do NOT fall through to local).
    /// </summary>
    Task<ExternalAuthResult?> AuthenticateAsync(string username, string password, CancellationToken ct = default);
}

/// <summary>
/// Result of an external authentication attempt.
/// </summary>
public sealed class ExternalAuthResult
{
    /// <summary>Whether the authentication succeeded.</summary>
    public bool Succeeded { get; private init; }

    /// <summary>Unique identifier in the external system (DN, sub, UPN, etc.).</summary>
    public string? ExternalId { get; private init; }

    /// <summary>Display name from the external directory.</summary>
    public string? DisplayName { get; private init; }

    /// <summary>Email from the external directory.</summary>
    public string? Email { get; private init; }

    /// <summary>Phone from the external directory.</summary>
    public string? Phone { get; private init; }

    /// <summary>Given name (first name).</summary>
    public string? GivenName { get; private init; }

    /// <summary>Family name (last name).</summary>
    public string? FamilyName { get; private init; }

    /// <summary>Additional claims from the external system (department, title, etc.).</summary>
    public Dictionary<string, string>? AdditionalClaims { get; set; }

    /// <summary>Error message for failed authentication.</summary>
    public string? ErrorMessage { get; private init; }

    public static ExternalAuthResult Success(
        string externalId,
        string? displayName = null,
        string? email = null,
        string? phone = null,
        string? givenName = null,
        string? familyName = null,
        Dictionary<string, string>? additionalClaims = null) => new()
    {
        Succeeded = true,
        ExternalId = externalId,
        DisplayName = displayName,
        Email = email,
        Phone = phone,
        GivenName = givenName,
        FamilyName = familyName,
        AdditionalClaims = additionalClaims
    };

    public static ExternalAuthResult Failed(string message) => new()
    {
        Succeeded = false,
        ErrorMessage = message
    };
}
