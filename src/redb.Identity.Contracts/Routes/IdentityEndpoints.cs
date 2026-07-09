namespace redb.Identity.Contracts.Routes;

/// <summary>
/// All <c>direct-vm://</c> endpoint URIs and RouteIds for the Identity Server.
/// Single source of truth — no magic strings anywhere else.
/// </summary>
public static class IdentityEndpoints
{
    // ── Protocol endpoints (OpenIddict pipeline) ──

    public const string Token = "direct-vm://identity-token";
    public const string Authorize = "direct-vm://identity-authorize";
    /// <summary>Z6 (RFC 9126): Pushed Authorization Request endpoint.</summary>
    public const string PushedAuthorization = "direct-vm://identity-par";
    public const string Userinfo = "direct-vm://identity-userinfo";
    public const string Introspect = "direct-vm://identity-introspect";
    public const string Revoke = "direct-vm://identity-revoke";
    public const string Discovery = "direct-vm://identity-discovery";
    public const string Jwks = "direct-vm://identity-jwks";
    public const string Logout = "direct-vm://identity-logout";
    public const string Device = "direct-vm://identity-device";
    public const string Verification = "direct-vm://identity-verification";
    public const string Login = "direct-vm://identity-login";
    public const string ConsentGrant = "direct-vm://identity-consent-grant";
    public const string DynamicRegister = "direct-vm://identity-dynamic-register";
    /// <summary>Z2 (RFC 7592): Dynamic Client Registration management endpoint.</summary>
    public const string DynamicRegisterManage = "direct-vm://identity-dynamic-register-manage";
    public const string MfaVerify = "direct-vm://identity-mfa-verify";
    public const string MfaRecovery = "direct-vm://identity-mfa-recovery";
    public const string MfaChallenge = "direct-vm://identity-mfa-challenge";
    /// <summary>B9 / BUG-9: Auth0-style gated enumeration of the user's MFA methods.</summary>
    public const string MfaListMethods = "direct-vm://identity-mfa-methods";

    /// <summary>
    /// MFA-3: WebAuthn login-flow assertion endpoint. Begin issues a fresh challenge wrapped
    /// in <c>mfa_state</c>; complete verifies the assertion and creates a session in the same
    /// transaction as <see cref="MfaVerify"/>.
    /// </summary>
    public const string MfaWebAuthn = "direct-vm://identity-mfa-webauthn";

    // ── Management endpoints ──

    public const string ManageApps = "direct-vm://identity-manage-apps";
    public const string ManageScopes = "direct-vm://identity-manage-scopes";
    public const string ManageUsers = "direct-vm://identity-manage-users";
    public const string ManageTokens = "direct-vm://identity-manage-tokens";
    public const string ManageGroups = "direct-vm://identity-manage-groups";
    public const string ManageConsents = "direct-vm://identity-manage-consents";
    public const string ManageSessions = "direct-vm://identity-manage-sessions";

    /// <summary>
    /// Admin signing-key lifecycle management. Operations:
    /// <list type="bullet">
    ///   <item><c>list</c> — every key row in the PROPS signing-key store, including retired ones.</item>
    ///   <item><c>rotate</c> — mint a new active key of the supplied kind; demote previously-active keys
    ///   of that kind (they stay in JWKS until their NotAfter passes).</item>
    ///   <item><c>retire</c> — set NotAfter of the supplied kid to "now"; the key disappears from JWKS
    ///   on the next request and tokens signed under it stop validating.</item>
    /// </list>
    /// Requires <c>identity:applications.manage</c> or master <c>identity:manage</c>.
    /// </summary>
    public const string ManageSigningKeys = "direct-vm://identity-manage-signing-keys";

    /// <summary>
    /// W6-0: Backchannel revoked-sids list. Operations:
    /// <list type="bullet">
    ///   <item><c>add</c> — publish a new revocation entry (sid, sub or both).</item>
    ///   <item><c>since</c> — incremental poll: returns entries with <c>RevokedAt &gt; cursor</c>.</item>
    /// </list>
    /// Used by Relying Parties (incl. our own <c>Identity.Web</c>) to invalidate cookie sessions
    /// in multi-instance deployments where the OIDC backchannel logout (<c>/bcl/sink</c>) push
    /// alone is insufficient to fan out across all replicas.
    /// </summary>
    public const string RevokedSids = "direct-vm://identity-revoked-sids";

    public const string MfaManage = "direct-vm://identity-manage-mfa";
    /// <summary>H9 (v1.0 DoD): Admin audit log query endpoint.</summary>
    public const string ManageAudit = "direct-vm://identity-manage-audit";

    /// <summary>
    /// N7-3 — admin impersonation session marker. Operations: <c>start</c>, <c>stop</c>.
    /// Does NOT mint a token; the BFF tracks the target user in its own session cookie
    /// and routes admin API calls accordingly. This endpoint writes audit events
    /// (<c>UserImpersonationStarted</c> / <c>UserImpersonationStopped</c>) and validates
    /// the target user exists.
    /// </summary>
    public const string ManageImpersonation = "direct-vm://identity-manage-impersonation";
    /// <summary>H5 (v1.0 DoD §5): Admin CRUD for declarative claim mappers.</summary>
    public const string ManageClaimMappers = "direct-vm://identity-manage-claim-mappers";
    /// <summary>H5 (v1.0 DoD §5): Admin CRUD for reusable Client Scopes (mapper bundles).</summary>
    public const string ManageClaimScopes = "direct-vm://identity-manage-claim-scopes";
    /// <summary>S2: Admin CRUD for claim definitions (schema with required + type + regex).</summary>
    public const string ManageClaimDefinitions = "direct-vm://identity-manage-claim-definitions";
    /// <summary>B.3: Admin CRUD + assignments for the Roles registry.</summary>
    public const string ManageRoles = "direct-vm://identity-manage-roles";
    /// <summary>W1: Admin CRUD for outbound webhook subscriptions.</summary>
    public const string ManageWebhooks = "direct-vm://identity-manage-webhooks";
    /// <summary>W1: Internal dispatcher route — consumes events route wiretap, fans out to subscriptions.</summary>
    public const string DispatchWebhooks = "direct-vm://identity-dispatch-webhooks";
    /// <summary>
    /// H3-SSO (v1.0 DoD §6 scoped-subset): Self-service session endpoint. Caller targets
    /// their own sessions only — userId is derived from the authenticated token subject,
    /// never from the request body.
    /// </summary>
    public const string MeSessions = "direct-vm://identity-me-sessions";

    /// <summary>
    /// H3 (v1.0 DoD §6): Self-service profile endpoint (<c>GET /me</c>, <c>PUT /me</c>).
    /// Caller id is derived from the authenticated token subject.
    /// </summary>
    public const string MeProfile = "direct-vm://identity-me-profile";

    /// <summary>
    /// H3 (v1.0 DoD §6): Self-service password change (<c>PUT /me/password</c>). Validates
    /// the caller's current password, enforces policy, and revokes all sessions on success
    /// (OWASP Session Management C7).
    /// </summary>
    public const string MePassword = "direct-vm://identity-me-password";

    /// <summary>
    /// N-4 (Session C): anonymous password-recovery initiation. Body =
    /// <c>PasswordForgotRequest</c>; always returns success (anti-enumeration). Validates
    /// <c>callerResetUrl</c> against the client's <c>ApplicationProps.PasswordResetUris</c>
    /// whitelist before issuing a single-use reset token and dispatching an e-mail.
    /// </summary>
    public const string PasswordForgot = "direct-vm://identity-password-forgot";

    /// <summary>
    /// N-4 (Session C): anonymous password-recovery completion. Body =
    /// <c>PasswordResetRequest</c>; verifies + atomically consumes the token, applies the
    /// new password, and revokes every active session for the bound user.
    /// </summary>
    public const string PasswordReset = "direct-vm://identity-password-reset";

    /// <summary>
    /// N-4 (Session C, sub-step N4-6): authenticated self-service request for an
    /// e-mail verification link. Body = <c>EmailVerifySendRequest</c> carrying
    /// <c>clientId</c> + <c>callerVerifyUrl</c>. The processor binds the token to the
    /// caller's current e-mail (derived from the access-token subject), so the user can
    /// never trigger a verify e-mail to someone else's inbox.
    /// </summary>
    public const string MeEmailVerifySend = "direct-vm://identity-me-email-verify-send";

    /// <summary>
    /// N-4 (Session C, sub-step N4-6): anonymous e-mail-verification confirmation.
    /// Body = <c>EmailVerifyConfirmRequest</c>; verifies + atomically consumes the token
    /// and sets <c>UserProps.EmailVerified = true</c> only when the user's current
    /// e-mail still matches the value bound at issue time.
    /// </summary>
    public const string EmailVerifyConfirm = "direct-vm://identity-email-verify-confirm";

    /// <summary>
    /// N-4 (Session E, sub-step N4-7): authenticated self-service request to switch the
    /// caller's e-mail to a new address. Body = <c>ChangeEmailRequestRequest</c> carrying
    /// <c>newEmail</c>, <c>clientId</c> + <c>callerConfirmUrl</c>. The processor issues a
    /// single-use token bound to BOTH the current and the requested new address and
    /// dispatches the confirmation link to the NEW address.
    /// </summary>
    public const string MeChangeEmailRequest = "direct-vm://identity-me-change-email-request";

    /// <summary>
    /// N-4 (Session E, sub-step N4-7): anonymous change-of-e-mail confirmation.
    /// Body = <c>ChangeEmailConfirmRequest</c>; verifies + atomically consumes the token,
    /// re-checks address uniqueness, then swaps <c>_users.email</c> to the new value AND
    /// flips <c>UserProps.EmailVerified = true</c> only when the caller's current e-mail
    /// still matches the snapshot captured at issue time.
    /// </summary>
    public const string ChangeEmailConfirm = "direct-vm://identity-change-email-confirm";

    /// <summary>
    /// N-3 (sub-step N3-7): anonymous self-service account registration. Body =
    /// <c>RegisterAccountRequest</c>; creates a new <c>_users</c> row + <c>UserProps</c>
    /// extension, optionally dispatches an e-mail verification link (when both
    /// <c>RedbIdentityOptions.Registration.SendVerifyEmail</c> and
    /// <c>RedbIdentityOptions.EmailVerification.Enabled</c> are <c>true</c>) and returns
    /// the new user id so the BFF can immediately sign the user in via ROPC. Returns
    /// <c>404</c> when <c>RedbIdentityOptions.Registration.Enabled</c> is <c>false</c>.
    /// </summary>
    public const string AccountRegister = "direct-vm://identity-account-register";

    /// <summary>
    /// N-4 (Session C): transactional e-mail dispatch backbone. The body of the inbound
    /// exchange is the rendered HTML (with <c>redbMail.*</c> headers carrying To/Subject/
    /// TextBody/From). Wired to <c>Smtp.Send(...)</c> via the redb.Route.Mail DSL when
    /// <c>RedbIdentityOptions.Smtp.Enabled</c> is <c>true</c>. When disabled the route is
    /// not built and the channel falls back to a host-registered alternative (e.g. the
    /// in-memory channel used by integration tests).
    /// </summary>
    public const string EmailSend = "direct-vm://identity-email-send";

    /// <summary>
    /// H3 (v1.0 DoD §6): Self-service MFA management (<c>/me/mfa/*</c>). Supports status,
    /// setup, confirm-setup, disable, regenerate-recovery — always scoped to the caller.
    /// </summary>
    public const string MeMfa = "direct-vm://identity-me-mfa";

    /// <summary>
    /// H3 (v1.0 DoD §6): Self-service consent management (<c>GET /me/consents</c>,
    /// <c>DELETE /me/consents/{clientId}</c>).
    /// </summary>
    public const string MeConsents = "direct-vm://identity-me-consents";

    /// <summary>
    /// MFA-3: Self-service WebAuthn management (<c>/me/webauthn/*</c>). Supports status,
    /// register-begin, register-complete, list/rename/delete credentials — always scoped to the caller.
    /// </summary>
    public const string MeWebAuthn = "direct-vm://identity-me-webauthn";

    // ── SCIM 2.0 endpoints (RFC 7644) ──

    public const string ScimUsers = "direct-vm://identity-scim-users";
    public const string ScimGroups = "direct-vm://identity-scim-groups";
    /// <summary>H1 (RFC 7644 §3.7): SCIM Bulk endpoint.</summary>
    public const string ScimBulk = "direct-vm://identity-scim-bulk";

    // ── Federation endpoints ──

    public const string FederationChallenge = "direct-vm://identity-federation-challenge";
    public const string FederationCallback = "direct-vm://identity-federation-callback";

    // H8 (DoD §4 gap (b)/(d)): self-service link/unlink of federated identities.
    public const string MeFederatedIdentities = "direct-vm://identity-me-federated-identities";

    // H8 (DoD §4 gap (e)): admin CRUD over PROPS-stored federation provider configs.
    public const string ManageFederationProviders = "direct-vm://identity-manage-federation-providers";

    // ── Event dispatch ──

    public const string Events = "direct-vm://identity-events";

    // ── Audit multicast ──

    public const string Audit = "direct-vm://identity-audit";

    // ── Phase 9d cross-context broker endpoints (Http facade → Core) ──

    /// <summary>
    /// Phase 9d. CORS preflight check: «is browser <c>Origin</c> registered as a
    /// redirect/post-logout URI of any OAuth client?». Body: <see cref="redb.Identity.Contracts.Cors.CorsCheckRequest"/>,
    /// reply: <see cref="redb.Identity.Contracts.Cors.CorsCheckResponse"/>. In-memory snapshot in Core,
    /// invalidation-driven; per-call cost &lt;1ms after warm-up.
    /// </summary>
    public const string CorsCheck = "direct-vm://identity-cors-check";

    /// <summary>
    /// Phase 9d. Validates an unauthenticated <c>post_logout_redirect_uri</c> against
    /// registered OAuth clients. Body: <see cref="redb.Identity.Contracts.Endpoints.ValidatePostLogoutRedirectRequest"/>,
    /// reply: <see cref="redb.Identity.Contracts.Endpoints.ValidatePostLogoutRedirectResponse"/>.
    /// </summary>
    public const string ValidatePostLogoutRedirect = "direct-vm://identity-validate-post-logout";

    /// <summary>
    /// Phase 9d. Decrypts an opaque <c>mfa_state</c> token and returns the configured MFA
    /// methods. Used by HTTP UI to render the verification page without taking a hard
    /// dependency on Core's <c>MfaStateProtector</c>. Body: <see cref="redb.Identity.Contracts.Mfa.MfaMethodsFromStateRequest"/>,
    /// reply: <see cref="redb.Identity.Contracts.Mfa.MfaMethodsFromStateResponse"/>.
    /// </summary>
    public const string MfaMethodsFromState = "direct-vm://identity-mfa-methods-from-state";

    // ── B1: one-shot emergency-admin bootstrap (chicken-and-egg) ──

    /// <summary>
    /// B1 — atomic create of the first admin user, group, OIDC client
    /// (<c>identity-web</c>) and <c>SystemFlag(bootstrap_completed)</c>. Body:
    /// <see cref="redb.Identity.Contracts.Endpoints.BootstrapAdminRequest"/>, reply:
    /// <see cref="redb.Identity.Contracts.Endpoints.BootstrapAdminResponse"/>. Mounted on the
    /// HTTP facade as <c>POST /internal/bootstrap-admin</c> (outside the regular base path).
    /// Self-locks via the <c>SystemFlag</c> sentinel — second call returns <c>410 Gone</c>.
    /// </summary>
    public const string BootstrapAdmin = "direct-vm://identity-bootstrap-admin";

    // ── Cross-context auth processor entry points (Phase 9b clean rewire) ──

    /// <summary>
    /// Validates the management API bearer token and accepts either the
    /// <c>identity:manage</c> or <c>identity:account</c> scope. The HTTP facade
    /// in its own Tsak context calls this endpoint inline as the first step of
    /// every <c>/api/v1/identity/*</c> and <c>/me/*</c> route — same exchange,
    /// synchronous, zero-copy via <c>direct-vm</c>.
    /// </summary>
    public const string AuthManagement = "direct-vm://identity-auth-management";

    /// <summary>
    /// Validates SCIM API bearer tokens (<c>scim</c> scope). Registered only when
    /// <c>Features.EnableScim = true</c>. Same usage pattern as
    /// <see cref="AuthManagement"/>.
    /// </summary>
    public const string AuthScim = "direct-vm://identity-auth-scim";

    // ── Route IDs ──

    public static class RouteIds
    {
        public const string Token = "identity-token";
        public const string Authorize = "identity-authorize";
        public const string PushedAuthorization = "identity-par";
        public const string Userinfo = "identity-userinfo";
        public const string Introspect = "identity-introspect";
        public const string Revoke = "identity-revoke";
        public const string Discovery = "identity-discovery";
        public const string Jwks = "identity-jwks";
        public const string Logout = "identity-logout";
        public const string Device = "identity-device";
        public const string Verification = "identity-verification";
        public const string Login = "identity-login";
        public const string ConsentGrant = "identity-consent-grant";
        public const string DynamicRegister = "identity-dynamic-register";
        public const string DynamicRegisterManage = "identity-dynamic-register-manage";
        public const string MfaVerify = "identity-mfa-verify";
        public const string MfaRecovery = "identity-mfa-recovery";
        public const string MfaChallenge = "identity-mfa-challenge";
        public const string MfaListMethods = "identity-mfa-methods";
        public const string MfaWebAuthn = "identity-mfa-webauthn";

        public const string ManageApps = "identity-manage-apps";
        public const string ManageScopes = "identity-manage-scopes";
        public const string ManageUsers = "identity-manage-users";
        public const string ManageTokens = "identity-manage-tokens";
        public const string ManageGroups = "identity-manage-groups";
        public const string ManageConsents = "identity-manage-consents";
        public const string ManageSessions = "identity-manage-sessions";
        public const string ManageSigningKeys = "identity-manage-signing-keys";
        public const string RevokedSids = "identity-revoked-sids";
        public const string RevokedSidsCleanup = "identity-revoked-sids-cleanup";
        public const string MfaManage = "identity-manage-mfa";
        public const string ManageAudit = "identity-manage-audit";
        public const string ManageImpersonation = "identity-manage-impersonation";
        public const string ManageClaimMappers = "identity-manage-claim-mappers";
        public const string ManageClaimScopes = "identity-manage-claim-scopes";
        public const string ManageClaimDefinitions = "identity-manage-claim-definitions";
        public const string ManageRoles = "identity-manage-roles";
        public const string ManageWebhooks = "identity-manage-webhooks";
        public const string DispatchWebhooks = "identity-dispatch-webhooks";
        public const string MeSessions = "identity-me-sessions";
        public const string MeProfile = "identity-me-profile";
        public const string MePassword = "identity-me-password";
        public const string PasswordForgot = "identity-password-forgot";
        public const string PasswordReset = "identity-password-reset";
        public const string MeEmailVerifySend = "identity-me-email-verify-send";
        public const string EmailVerifyConfirm = "identity-email-verify-confirm";
        public const string MeChangeEmailRequest = "identity-me-change-email-request";
        public const string ChangeEmailConfirm = "identity-change-email-confirm";
        public const string AccountRegister = "identity-account-register";
        public const string EmailSend = "identity-email-send";
        public const string MeMfa = "identity-me-mfa";
        public const string MeConsents = "identity-me-consents";
        public const string MeWebAuthn = "identity-me-webauthn";

        public const string ScimUsers = "identity-scim-users";
        public const string ScimGroups = "identity-scim-groups";
        public const string ScimBulk = "identity-scim-bulk";

        public const string FederationChallenge = "identity-federation-challenge";
        public const string FederationCallback = "identity-federation-callback";
        public const string MeFederatedIdentities = "identity-me-federated-identities";
        public const string ManageFederationProviders = "identity-manage-federation-providers";

        public const string Events = "identity-events";
        public const string Audit = "identity-audit";

        // Phase 9d cross-context broker route ids.
        public const string CorsCheck = "identity-cors-check";
        public const string ValidatePostLogoutRedirect = "identity-validate-post-logout";
        public const string MfaMethodsFromState = "identity-mfa-methods-from-state";

        // B1: one-shot emergency-admin bootstrap.
        public const string BootstrapAdmin = "identity-bootstrap-admin";

        // Cross-context auth processor entry points.
        public const string AuthManagement = "identity-auth-management";
        public const string AuthScim = "identity-auth-scim";
    }
}
