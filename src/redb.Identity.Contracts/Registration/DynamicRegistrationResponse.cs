using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Registration;

/// <summary>
/// RFC 7591 §3.2.1 Client Information Response for Dynamic Client Registration.
/// </summary>
public sealed class DynamicRegistrationResponse
{
    [JsonPropertyName("client_id")]
    public string ClientId { get; set; } = default!;

    [JsonPropertyName("client_secret")]
    public string? ClientSecret { get; set; }

    [JsonPropertyName("client_secret_expires_at")]
    public long? ClientSecretExpiresAt { get; set; }

    [JsonPropertyName("client_id_issued_at")]
    public long? ClientIdIssuedAt { get; set; }

    [JsonPropertyName("redirect_uris")]
    public string[]? RedirectUris { get; set; }

    [JsonPropertyName("token_endpoint_auth_method")]
    public string? TokenEndpointAuthMethod { get; set; }

    [JsonPropertyName("grant_types")]
    public string[]? GrantTypes { get; set; }

    [JsonPropertyName("response_types")]
    public string[]? ResponseTypes { get; set; }

    [JsonPropertyName("client_name")]
    public string? ClientName { get; set; }

    [JsonPropertyName("client_uri")]
    public string? ClientUri { get; set; }

    [JsonPropertyName("logo_uri")]
    public string? LogoUri { get; set; }

    [JsonPropertyName("scope")]
    public string? Scope { get; set; }

    [JsonPropertyName("contacts")]
    public string[]? Contacts { get; set; }

    [JsonPropertyName("software_id")]
    public string? SoftwareId { get; set; }

    [JsonPropertyName("software_version")]
    public string? SoftwareVersion { get; set; }

    [JsonPropertyName("application_type")]
    public string? ApplicationType { get; set; }

    [JsonPropertyName("post_logout_redirect_uris")]
    public string[]? PostLogoutRedirectUris { get; set; }

    /// <summary>RFC 7591 §3.2.1 — echoed JWKS when the client registered with <c>private_key_jwt</c> + inline <c>jwks</c>.</summary>
    [JsonPropertyName("jwks")]
    public System.Text.Json.JsonElement? JsonWebKeySet { get; set; }

    /// <summary>RFC 7591 §3.2.1 — echoed JWKS URI when the client registered with <c>private_key_jwt</c> + <c>jwks_uri</c>.</summary>
    [JsonPropertyName("jwks_uri")]
    public string? JsonWebKeySetUri { get; set; }

    /// <summary>RFC 7592 §3: one-time bearer token granting access to the client configuration endpoint.</summary>
    [JsonPropertyName("registration_access_token")]
    public string? RegistrationAccessToken { get; set; }

    /// <summary>RFC 7592 §3: absolute URL of the client configuration endpoint for this client.</summary>
    [JsonPropertyName("registration_client_uri")]
    public string? RegistrationClientUri { get; set; }

    /// <summary>RFC 9126 §5 — echoed per-client PAR-enforcement flag.</summary>
    [JsonPropertyName("require_pushed_authorization_requests")]
    public bool? RequirePushedAuthorizationRequests { get; set; }

    /// <summary>N-4 (Session C) — echoed per-client password-reset URL whitelist.</summary>
    [JsonPropertyName("password_reset_uris")]
    public string[]? PasswordResetUris { get; set; }

    /// <summary>N-4 (Session C, N4-6) — echoed per-client verify-email URL whitelist.</summary>
    [JsonPropertyName("email_verify_uris")]
    public string[]? EmailVerifyUris { get; set; }

    /// <summary>N-4 (Session E, N4-7) — echoed per-client change-email URL whitelist.</summary>
    [JsonPropertyName("change_email_uris")]
    public string[]? ChangeEmailUris { get; set; }
}
