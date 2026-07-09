using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace redb.Identity.Contracts.Applications;

public sealed class UpdateApplicationRequest
{
    [Required(AllowEmptyStrings = false, ErrorMessage = "id is required.")]
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("displayName")]
    public string? DisplayName { get; set; }

    [JsonPropertyName("clientType")]
    public string? ClientType { get; set; }

    [JsonPropertyName("consentType")]
    public string? ConsentType { get; set; }

    [JsonPropertyName("permissions")]
    public string[]? Permissions { get; set; }

    [JsonPropertyName("redirectUris")]
    public string[]? RedirectUris { get; set; }

    [JsonPropertyName("postLogoutRedirectUris")]
    public string[]? PostLogoutRedirectUris { get; set; }

    [JsonPropertyName("requirements")]
    public string[]? Requirements { get; set; }

    /// <summary>
    /// N-4 (Session C): allowed password-reset landing URIs. The <c>callerResetUrl</c>
    /// on <c>/api/v1/identity/password/forgot</c> must exactly match one of these
    /// (string compare). <c>null</c>/empty disables the password-recovery flow for this client.
    /// </summary>
    [JsonPropertyName("passwordResetUris")]
    public string[]? PasswordResetUris { get; set; }

    /// <summary>
    /// N-4 (Session C, N4-6): allowed e-mail-verification landing URIs. Same shape as
    /// <see cref="PasswordResetUris"/> but for the verify-email flow.
    /// </summary>
    [JsonPropertyName("emailVerifyUris")]
    public string[]? EmailVerifyUris { get; set; }

    /// <summary>
    /// N-4 (Session E, N4-7): allowed change-of-e-mail confirmation landing URIs. Same
    /// shape as <see cref="PasswordResetUris"/> but for the change-email flow.
    /// </summary>
    [JsonPropertyName("changeEmailUris")]
    public string[]? ChangeEmailUris { get; set; }

    [JsonPropertyName("concurrencyToken")]
    public string? ConcurrencyToken { get; set; }

    /// <summary>
    /// OIDC Back-Channel Logout 1.0 §2.2 endpoint. Empty string clears the
    /// existing value; null leaves it unchanged (PATCH semantics).
    /// </summary>
    [JsonPropertyName("backchannelLogoutUri")]
    public string? BackchannelLogoutUri { get; set; }

    /// <summary>
    /// OIDC Back-Channel Logout 1.0 §2.2 — sid inclusion flag. Null leaves
    /// the existing value unchanged.
    /// </summary>
    [JsonPropertyName("backchannelLogoutSessionRequired")]
    public bool? BackchannelLogoutSessionRequired { get; set; }

    /// <summary>
    /// OAuth 2.1 §4.4 / RFC 9126 PAR mandatory flag. Null leaves the existing
    /// value unchanged.
    /// </summary>
    [JsonPropertyName("requirePushedAuthorizationRequests")]
    public bool? RequirePushedAuthorizationRequests { get; set; }

    /// <summary>
    /// RFC 7517 JWKS document attached to this client. Empty string clears the
    /// stored JWKS; null leaves it unchanged.
    /// </summary>
    [JsonPropertyName("jsonWebKeySet")]
    public string? JsonWebKeySet { get; set; }

    /// <summary>
    /// Per-client access-token lifetime in seconds. PATCH semantics: null leaves
    /// unchanged, 0 (or negative) clears the override and reverts to the global
    /// default, positive sets the new lifetime.
    /// </summary>
    [JsonPropertyName("accessTokenLifetimeSeconds")]
    public int? AccessTokenLifetimeSeconds { get; set; }

    /// <summary>
    /// Per-client refresh-token lifetime in seconds. Same semantics as
    /// <see cref="AccessTokenLifetimeSeconds"/>.
    /// </summary>
    [JsonPropertyName("refreshTokenLifetimeSeconds")]
    public int? RefreshTokenLifetimeSeconds { get; set; }

    /// <summary>
    /// Per-client id_token lifetime in seconds. Same semantics as
    /// <see cref="AccessTokenLifetimeSeconds"/>.
    /// </summary>
    [JsonPropertyName("identityTokenLifetimeSeconds")]
    public int? IdentityTokenLifetimeSeconds { get; set; }

    /// <summary>
    /// Extra audiences appended to issued <c>id_token</c>s. Null leaves the
    /// existing list unchanged; an empty array clears all extra audiences
    /// (the client_id default still applies).
    /// </summary>
    [JsonPropertyName("idTokenAudiences")]
    public string[]? IdTokenAudiences { get; set; }

    /// <summary>
    /// A.6: RFC 9101 — JWT signing alg for the request object. Empty string clears,
    /// null leaves unchanged. Advisory until JAR enforcement handler ships.
    /// </summary>
    [JsonPropertyName("requestObjectSigningAlg")]
    public string? RequestObjectSigningAlg { get; set; }

    /// <summary>A.6: JWE alg for the request object. Same PATCH semantics.</summary>
    [JsonPropertyName("requestObjectEncryptionAlg")]
    public string? RequestObjectEncryptionAlg { get; set; }

    /// <summary>A.6: JWE enc for the request object. Same PATCH semantics.</summary>
    [JsonPropertyName("requestObjectEncryptionEnc")]
    public string? RequestObjectEncryptionEnc { get; set; }

    /// <summary>
    /// A.7: client JWKS endpoint URL. Empty string clears, null leaves alone.
    /// </summary>
    [JsonPropertyName("jwksUri")]
    public string? JwksUri { get; set; }

    /// <summary>
    /// A.8: RFC 9449 — per-client strict DPoP opt-in. Null leaves alone.
    /// </summary>
    [JsonPropertyName("requireDpop")]
    public bool? RequireDpop { get; set; }

    /// <summary>A.10: skip RP-initiated logout consent. Null leaves alone.</summary>
    [JsonPropertyName("skipLogoutConsent")]
    public bool? SkipLogoutConsent { get; set; }

    /// <summary>A.10: FIDO trusted flag. Null leaves alone.</summary>
    [JsonPropertyName("isFidoTrusted")]
    public bool? IsFidoTrusted { get; set; }

    /// <summary>
    /// β: AllowedGroups whitelist (group names). Null leaves alone; empty array
    /// clears the whitelist (any user can use the app again).
    /// </summary>
    [JsonPropertyName("allowedGroups")]
    public string[]? AllowedGroups { get; set; }
}
