using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Applications;

public sealed class ApplicationResponse
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("clientId")]
    public string? ClientId { get; set; }

    [JsonPropertyName("displayName")]
    public string? DisplayName { get; set; }

    [JsonPropertyName("clientType")]
    public string? ClientType { get; set; }

    [JsonPropertyName("consentType")]
    public string? ConsentType { get; set; }

    [JsonPropertyName("applicationType")]
    public string? ApplicationType { get; set; }

    [JsonPropertyName("permissions")]
    public string[]? Permissions { get; set; }

    [JsonPropertyName("redirectUris")]
    public string[]? RedirectUris { get; set; }

    [JsonPropertyName("postLogoutRedirectUris")]
    public string[]? PostLogoutRedirectUris { get; set; }

    [JsonPropertyName("requirements")]
    public string[]? Requirements { get; set; }

    [JsonPropertyName("passwordResetUris")]
    public string[]? PasswordResetUris { get; set; }

    [JsonPropertyName("emailVerifyUris")]
    public string[]? EmailVerifyUris { get; set; }

    [JsonPropertyName("changeEmailUris")]
    public string[]? ChangeEmailUris { get; set; }

    [JsonPropertyName("concurrencyToken")]
    public string? ConcurrencyToken { get; set; }

    /// <summary>
    /// OIDC Back-Channel Logout 1.0 §2.2 endpoint. Absolute HTTPS (or http for
    /// localhost/dev) URL the server POSTs a signed <c>logout_token</c> to when
    /// the user's session is terminated. Null/empty disables back-channel
    /// logout for this client.
    /// </summary>
    [JsonPropertyName("backchannelLogoutUri")]
    public string? BackchannelLogoutUri { get; set; }

    /// <summary>
    /// OIDC Back-Channel Logout 1.0 §2.2 — when true, the dispatched
    /// <c>logout_token</c> includes a <c>sid</c> claim so the RP can
    /// invalidate the matching session. Defaults to true (RFC-recommended).
    /// </summary>
    [JsonPropertyName("backchannelLogoutSessionRequired")]
    public bool? BackchannelLogoutSessionRequired { get; set; }

    /// <summary>
    /// OAuth 2.1 §4.4 / RFC 9126 PAR mandatory flag. When true, this client's
    /// authorization requests must come via /connect/par first; direct calls to
    /// /connect/authorize are rejected with <c>par_required</c>. Null is false.
    /// </summary>
    [JsonPropertyName("requirePushedAuthorizationRequests")]
    public bool? RequirePushedAuthorizationRequests { get; set; }

    /// <summary>
    /// RFC 7517 JWKS document attached to this client. Used for (a) verifying
    /// the JWT bearer assertion when this client authenticates with
    /// <c>client_secret_jwt</c> / <c>private_key_jwt</c>, and (b) encrypting
    /// the issued <c>id_token</c> when ID-Token encryption is enabled.
    /// </summary>
    [JsonPropertyName("jsonWebKeySet")]
    public string? JsonWebKeySet { get; set; }

    /// <summary>
    /// Per-client access-token lifetime in seconds. Null means "use the global
    /// <see cref="redb.Identity.Core.Configuration.RedbIdentityOptions.AccessTokenLifetime"/>
    /// default" (1 h). Set to override only for this client — matches WSO2 IS 7.x
    /// "User access token expiry time".
    /// </summary>
    [JsonPropertyName("accessTokenLifetimeSeconds")]
    public int? AccessTokenLifetimeSeconds { get; set; }

    /// <summary>
    /// Per-client refresh-token lifetime in seconds. Null = global default (14 d).
    /// </summary>
    [JsonPropertyName("refreshTokenLifetimeSeconds")]
    public int? RefreshTokenLifetimeSeconds { get; set; }

    /// <summary>
    /// Per-client id_token lifetime in seconds. Null = global default (5 min).
    /// Matches WSO2 IS 7.x "ID Token expiry time".
    /// </summary>
    [JsonPropertyName("identityTokenLifetimeSeconds")]
    public int? IdentityTokenLifetimeSeconds { get; set; }

    /// <summary>
    /// Extra audiences appended to issued <c>id_token</c>s. The client's own
    /// <c>client_id</c> is always included as an audience by default (OIDC core §2);
    /// these entries broaden the audience set so federated downstream resource
    /// servers can also accept the id_token. Matches WSO2 IS 7.x "Audience".
    /// </summary>
    [JsonPropertyName("idTokenAudiences")]
    public string[]? IdTokenAudiences { get; set; }

    /// <summary>A.6: RFC 9101 — JWT signing alg for the request object. Advisory.</summary>
    [JsonPropertyName("requestObjectSigningAlg")]
    public string? RequestObjectSigningAlg { get; set; }

    /// <summary>A.6: JWE alg for the request object. Advisory.</summary>
    [JsonPropertyName("requestObjectEncryptionAlg")]
    public string? RequestObjectEncryptionAlg { get; set; }

    /// <summary>A.6: JWE enc for the request object. Advisory.</summary>
    [JsonPropertyName("requestObjectEncryptionEnc")]
    public string? RequestObjectEncryptionEnc { get; set; }

    /// <summary>
    /// A.7: client JWKS endpoint URL (RFC 7591 §2). Mutually exclusive with the
    /// inline <see cref="JsonWebKeySet"/> field at the UI layer.
    /// </summary>
    [JsonPropertyName("jwksUri")]
    public string? JwksUri { get; set; }

    /// <summary>
    /// A.8: RFC 9449 — per-client opt-in to strict DPoP mode at the token endpoint.
    /// Null is treated as false.
    /// </summary>
    [JsonPropertyName("requireDpop")]
    public bool? RequireDpop { get; set; }

    /// <summary>A.10: skip RP-initiated logout consent prompt for this app.</summary>
    [JsonPropertyName("skipLogoutConsent")]
    public bool? SkipLogoutConsent { get; set; }

    /// <summary>A.10: mark application as a FIDO trusted relying party.</summary>
    [JsonPropertyName("isFidoTrusted")]
    public bool? IsFidoTrusted { get; set; }

    /// <summary>
    /// β: whitelist of group names allowed to authenticate against this app.
    /// Null/empty = any authenticated user.
    /// </summary>
    [JsonPropertyName("allowedGroups")]
    public string[]? AllowedGroups { get; set; }

    /// <summary>
    /// Plaintext client secret. Populated <b>only</b> by the rotate-secret endpoint
    /// (the one-time response that displays the freshly generated secret). All other
    /// list / read / create / update responses leave this <c>null</c> by design —
    /// secrets are stored as BCrypt hashes and cannot be recovered. Callers must
    /// persist the value immediately; subsequent reads will never expose it again.
    /// </summary>
    [JsonPropertyName("newSecret")]
    public string? NewSecret { get; set; }
}
