using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Registration;

/// <summary>
/// RFC 7591 §2 Client Metadata for Dynamic Client Registration.
/// </summary>
public sealed class DynamicRegistrationRequest
{
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

    /// <summary>
    /// RFC 7591 §2 — JSON Web Key Set carrying the client's <i>public</i> keys for
    /// <c>private_key_jwt</c> client authentication (RFC 7523). Required when
    /// <see cref="TokenEndpointAuthMethod"/> is <c>private_key_jwt</c> and
    /// <see cref="JsonWebKeySetUri"/> is not provided. Stored verbatim and consulted
    /// when verifying the JWT-bearer client assertion signature.
    /// </summary>
    [JsonPropertyName("jwks")]
    public System.Text.Json.JsonElement? JsonWebKeySet { get; set; }

    /// <summary>
    /// RFC 7591 §2 — URL referencing the client's JSON Web Key Set. The server
    /// MUST NOT host both <c>jwks</c> and <c>jwks_uri</c>. Optional alternative
    /// to <see cref="JsonWebKeySet"/> for <c>private_key_jwt</c> clients.
    /// </summary>
    [JsonPropertyName("jwks_uri")]
    public string? JsonWebKeySetUri { get; set; }

    /// <summary>
    /// OIDC Back-Channel Logout 1.0 §2.2 — absolute HTTPS (or http for
    /// localhost/dev) URL the server POSTs the signed <c>logout_token</c> to
    /// when the user's session is terminated. Stored as a custom property
    /// (<c>backchannel_logout_uri</c>) on the registered application.
    /// </summary>
    [JsonPropertyName("backchannel_logout_uri")]
    public string? BackchannelLogoutUri { get; set; }

    /// <summary>
    /// OIDC Back-Channel Logout 1.0 §2.2 — when true the dispatched
    /// <c>logout_token</c> includes a <c>sid</c> claim. Defaults to true when
    /// <see cref="BackchannelLogoutUri"/> is set.
    /// </summary>
    [JsonPropertyName("backchannel_logout_session_required")]
    public bool? BackchannelLogoutSessionRequired { get; set; }

    /// <summary>
    /// RFC 9126 §5 — opt this client into per-client PAR enforcement: any direct
    /// <c>/connect/authorize</c> request without a <c>request_uri</c> issued by
    /// <c>/connect/par</c> will be rejected with <c>invalid_request</c>. Layers
    /// independently on top of the global <c>RequirePushedAuthorizationRequests</c>
    /// server flag so a single client can demand PAR even if other clients don't.
    /// </summary>
    [JsonPropertyName("require_pushed_authorization_requests")]
    public bool? RequirePushedAuthorizationRequests { get; set; }

    /// <summary>
    /// N-4 (Session C) — RFC 7591 §2 client_metadata extension:
    /// allowed password-reset landing URIs. The caller-supplied <c>callerResetUrl</c>
    /// on <c>POST /api/v1/identity/password/forgot</c> must exactly match one of these
    /// (string compare, no normalization). <c>null</c>/empty disables password recovery
    /// for this client. Use a list (not a single URI) so multi-environment BFFs can
    /// register dev / staging / prod pages on the same client.
    /// </summary>
    [JsonPropertyName("password_reset_uris")]
    public string[]? PasswordResetUris { get; set; }

    /// <summary>
    /// N-4 (Session C, N4-6) — RFC 7591 §2 client_metadata extension:
    /// allowed e-mail-verification landing URIs. Same shape and matching rules as
    /// <see cref="PasswordResetUris"/>.
    /// </summary>
    [JsonPropertyName("email_verify_uris")]
    public string[]? EmailVerifyUris { get; set; }

    /// <summary>
    /// N-4 (Session E, N4-7) — RFC 7591 §2 client_metadata extension:
    /// allowed change-of-e-mail confirmation landing URIs. Same shape and matching
    /// rules as <see cref="PasswordResetUris"/>.
    /// </summary>
    [JsonPropertyName("change_email_uris")]
    public string[]? ChangeEmailUris { get; set; }
}
