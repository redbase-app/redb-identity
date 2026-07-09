using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// PROPS Props for OAuth 2.0 / OpenID Connect client application.
/// Base fields: name = display name, hash = concurrency token.
/// </summary>
[RedbScheme("identity.application")]
public class ApplicationProps
{
    /// <summary>
    /// OAuth client_id (unique).
    /// Stored in root <c>_objects.value_string</c> (indexed), not in PROPS.
    /// </summary>
    [RedbIgnore]
    public string? ClientId { get; set; }

    /// <summary>Hashed client_secret (confidential clients only).</summary>
    public string? ClientSecret { get; set; }

    /// <summary>"public" or "confidential".</summary>
    public string? ClientType { get; set; }

    /// <summary>"explicit", "implicit", or "external".</summary>
    public string? ConsentType { get; set; }

    /// <summary>"web" or "native".</summary>
    public string? ApplicationType { get; set; }

    /// <summary>Granted permissions: ["ept:token", "gt:authorization_code", "scp:openid"].</summary>
    public string[]? Permissions { get; set; }

    /// <summary>Allowed redirect URIs (authorization_code flow).</summary>
    public string[]? RedirectUris { get; set; }

    /// <summary>Allowed post-logout redirect URIs.</summary>
    public string[]? PostLogoutRedirectUris { get; set; }

    /// <summary>
    /// N-4 (Session C): allowed password-reset landing URIs. The caller-supplied
    /// <c>callerResetUrl</c> on <c>identity-password-forgot</c> must exactly match one of
    /// these (string compare, no normalization). When <c>null</c>/empty, password recovery
    /// is disabled for this client. Acts as an open-redirect whitelist analogous to
    /// <see cref="RedirectUris"/>; lives on the client (not OS-wide) so multi-tenant
    /// deployments can scope each BFF to its own reset page.
    /// </summary>
    public string[]? PasswordResetUris { get; set; }

    /// <summary>
    /// N-4 (Session C, sub-step N4-6): allowed e-mail-verification landing URIs.
    /// Mirrors <see cref="PasswordResetUris"/> for the verify-email flow — the
    /// <c>callerVerifyUrl</c> on <c>identity-me-email-verify-send</c> must exactly match
    /// one of these (string compare). When <c>null</c>/empty, e-mail verification is
    /// disabled for this client even when
    /// <c>RedbIdentityOptions.EmailVerification.Enabled = true</c>.
    /// </summary>
    public string[]? EmailVerifyUris { get; set; }

    /// <summary>
    /// N-4 (Session E, sub-step N4-7): allowed change-of-e-mail confirmation landing
    /// URIs. The <c>callerConfirmUrl</c> on <c>identity-me-change-email-request</c> must
    /// exactly match one of these (string compare). When <c>null</c>/empty, the strict
    /// change-of-e-mail flow is disabled for this client even when
    /// <c>RedbIdentityOptions.ChangeEmail.Enabled = true</c>.
    /// </summary>
    public string[]? ChangeEmailUris { get; set; }

    /// <summary>
    /// Optional OIDC Backchannel Logout endpoint (RFC: OIDC Back-Channel Logout 1.0).
    /// When set, on user logout the IdP POSTs a signed <c>logout_token</c> to this URL
    /// so the relying party can terminate its local session. Must be an absolute https URL
    /// in production.
    /// </summary>
    public string? BackchannelLogoutUri { get; set; }

    /// <summary>
    /// When <c>true</c>, the <c>logout_token</c> sent to <see cref="BackchannelLogoutUri"/>
    /// will include the <c>sid</c> (session id) claim. RP can use it to terminate only the
    /// matching session instead of all sessions for the user. Mirrors the OIDC client metadata
    /// field <c>backchannel_logout_session_required</c>.
    /// </summary>
    public bool BackchannelLogoutSessionRequired { get; set; }

    /// <summary>Requirements: ["ft:pkce"].</summary>
    public string[]? Requirements { get; set; }

    /// <summary>Localized display names: { "en": "My App", "ru": "Мой App" }.</summary>
    public Dictionary<string, string>? DisplayNames { get; set; }

    /// <summary>Extensible settings bag (OpenIddict Settings — string values).</summary>
    public Dictionary<string, string>? Settings { get; set; }

    /// <summary>Extensible properties bag (OpenIddict Properties — JSON values stored as raw text).</summary>
    public Dictionary<string, string>? Properties { get; set; }

    /// <summary>Serialized JSON Web Key Set (for client assertion).</summary>
    public string? JsonWebKeySet { get; set; }

    /// <summary>
    /// Z2 (RFC 7592): SHA-256 hex hash of the <c>registration_access_token</c> issued when
    /// the client was created via Dynamic Client Registration. <c>null</c> for clients created
    /// through the admin API. Consumed by <c>ClientRegistrationManagementProcessor</c> to
    /// authorize <c>GET/PUT/DELETE /connect/register/{client_id}</c>.
    /// </summary>
    public string? RegistrationAccessTokenHash { get; set; }

    /// <summary>
    /// RFC 9126 §5 — when <c>true</c>, the authorization server MUST reject any direct
    /// <c>/connect/authorize</c> request for this client that does not carry a valid
    /// <c>request_uri</c> (issued by <c>/connect/par</c>). Layered on top of the global
    /// <c>RedbIdentityOptions.RequirePushedAuthorizationRequests</c> flag so individual
    /// high-assurance clients (FAPI, financial APIs) can opt-in independently.
    /// </summary>
    public bool RequirePushedAuthorizationRequests { get; set; }

    /// <summary>
    /// Additional audiences attached to issued <c>id_token</c>s as extra entries
    /// in the <c>aud</c> claim. The client's own <c>client_id</c> is always
    /// included by OpenIddict (matches OIDC core §2 default). When this array is
    /// non-empty, <see cref="OpenIddict.Handlers.AttachAdditionalIdTokenAudiences"/>
    /// appends each entry as an additional <c>aud</c> value, allowing the same
    /// id_token to be consumed by federated downstream resource servers.
    /// </summary>
    public string[]? IdTokenAudiences { get; set; }

    /// <summary>
    /// A.6: RFC 9101 (JAR) — JWT signing algorithm the client is expected to use
    /// when sending a signed authorization request as <c>request</c> / <c>request_uri</c>.
    /// Stored as an advisory hint today (no enforcement gate yet); reserved keys
    /// follow the JOSE registry: <c>none</c>, <c>RS256</c>, <c>RS384</c>, <c>RS512</c>,
    /// <c>PS256</c>, <c>PS384</c>, <c>PS512</c>, <c>ES256</c>, <c>ES384</c>, <c>ES512</c>,
    /// <c>EdDSA</c>. Server-side enforcement is queued for a follow-up
    /// (would need a ProcessAuthenticationContext handler that rejects when the
    /// inbound JWT's alg disagrees with the stored value).
    /// </summary>
    public string? RequestObjectSigningAlg { get; set; }

    /// <summary>
    /// A.6: JWE algorithm for encrypting the request object (RFC 9101 §10.2).
    /// Advisory hint; same enforcement caveat as <see cref="RequestObjectSigningAlg"/>.
    /// </summary>
    public string? RequestObjectEncryptionAlg { get; set; }

    /// <summary>
    /// A.6: JWE encryption method for the request object (RFC 9101 §10.2).
    /// Advisory hint; same enforcement caveat as <see cref="RequestObjectSigningAlg"/>.
    /// </summary>
    public string? RequestObjectEncryptionEnc { get; set; }

    /// <summary>
    /// A.7: RFC 7591 §2 / RFC 7517 — client JWKS endpoint URL. When set, the
    /// authorization server fetches the JWKS from this absolute HTTPS URL at
    /// runtime to verify client assertions (<c>client_secret_jwt</c> /
    /// <c>private_key_jwt</c>) and to encrypt id_token destined for this client.
    /// Mutually exclusive with the inline <see cref="JsonWebKeySet"/> field —
    /// the admin UI's "Certificate type" radio enforces that contract at the
    /// presentation layer; the server tolerates both being set and prefers
    /// inline (cached) over endpoint (fetched) for correctness without breakage.
    /// </summary>
    public string? JwksUri { get; set; }

    /// <summary>
    /// A.8: RFC 9449 (DPoP) — per-client opt-in to strict mode. When true, the
    /// token endpoint rejects access-token requests from this client that don't
    /// carry a valid DPoP proof header with <c>invalid_dpop_proof</c>. Server-wide
    /// <see cref="DpopOptions.RequireForAccessTokens"/> still wins if it's true
    /// (it forces strict mode for every client). Default false (soft-mode — client
    /// may send a DPoP proof to upgrade to a sender-constrained access token).
    /// </summary>
    public bool RequireDpop { get; set; }

    /// <summary>
    /// A.10: skip the RP-initiated logout consent prompt for this application.
    /// When false (default), the user is shown a "Sign out of MyApp?" dialog
    /// before the session terminates; when true, the logout proceeds silently
    /// matching <c>id_token_hint</c> + <c>post_logout_redirect_uri</c>.
    /// </summary>
    public bool SkipLogoutConsent { get; set; }

    /// <summary>
    /// A.10: mark this application as a FIDO trusted relying party. When true,
    /// the WebAuthn assertion verification skips the extra "is this passkey
    /// from a trusted app?" check that we apply by default. Equivalent to
    /// WSO2 IS 7.x "Add as a FIDO trusted app".
    /// </summary>
    public bool IsFidoTrusted { get; set; }

    /// <summary>
    /// β: whitelist of group NAMES allowed to authenticate against this application.
    /// When null or empty (default) any authenticated user may use the app. When
    /// non-empty, <see cref="OpenIddict.Handlers.RestrictApplicationByGroupMembershipHandler"/>
    /// rejects sign-in with <c>access_denied</c> unless the user is a member of at
    /// least one listed group. Independent of and OR'd against the per-scope
    /// <c>RedbIdentityOptions.ScopeRequiredGroups</c> server config — both gates
    /// must pass.
    /// <para>
    /// Stored as group NAMES rather than ids so admin UI / operator can read it
    /// at a glance, matching the operator-mental-model that
    /// ScopeRequiredGroups already uses ("identity:manage" → "admins").
    /// </para>
    /// </summary>
    public string[]? AllowedGroups { get; set; }
}
