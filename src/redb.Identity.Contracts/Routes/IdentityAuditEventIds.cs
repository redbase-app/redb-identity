namespace redb.Identity.Contracts.Routes;

/// <summary>
/// H9 (v1.0 DoD): Centralized audit event catalog.
/// <para>
/// <b>Single source of truth</b> for every <c>identity-event-type</c> emitted anywhere in the
/// redb.Identity pipeline. All processors emitting <c>exchange.Properties["identity-event-type"]</c>
/// MUST use a constant from this class — never a magic string.
/// </para>
/// <para>
/// <see cref="CategoryOf(string)"/> resolves the semantic bucket stored in
/// the <c>identity_audit_log.category</c> column. Unknown event types resolve to
/// <see cref="IdentityAuditCategories.System"/> so forward-compatible custom events still land in storage.
/// </para>
/// </summary>
public static class IdentityAuditEventIds
{
    // ── authentication ──
    public const string UserLoggedIn = "UserLoggedIn";
    public const string UserLoggedOut = "UserLoggedOut";
    public const string LoginFailed = "LoginFailed";
    public const string PasswordChanged = "PasswordChanged";
    /// <summary>N-4 (Session C): password-recovery initiation. Always emitted, even when
    /// the e-mail does not resolve to a user (anti-enumeration). Payload carries the
    /// supplied e-mail (hashed) so abuse can be traced without disclosing victim identity.</summary>
    public const string PasswordResetRequested = "PasswordResetRequested";
    /// <summary>N-4 (Session C): a single-use reset token was issued AND e-mail dispatched
    /// (i.e. the request resolved to a real user with a whitelisted reset URL).</summary>
    public const string PasswordResetTokenIssued = "PasswordResetTokenIssued";
    /// <summary>N-4 (Session C): password-recovery completed successfully — token consumed,
    /// new password persisted, sessions revoked.</summary>
    public const string PasswordResetCompleted = "PasswordResetCompleted";
    /// <summary>N-4 (Session C): password-recovery attempt failed (bad / expired / consumed
    /// token, or policy violation). Used for guessing-attack telemetry.</summary>
    public const string PasswordResetFailed = "PasswordResetFailed";

    /// <summary>N-4 (Session C, N4-6): e-mail verification link was issued and dispatched
    /// to the user's inbox. Payload carries UserId, ClientId, Jti, target e-mail (lowercase).</summary>
    public const string EmailVerificationSent = "EmailVerificationSent";
    /// <summary>N-4 (Session C, N4-6): user confirmed e-mail verification \u2014 token consumed,
    /// <c>UserProps.EmailVerified</c> flipped to <c>true</c>.</summary>
    public const string EmailVerificationCompleted = "EmailVerificationCompleted";
    /// <summary>N-4 (Session C, N4-6): verify-email attempt failed (bad / expired / consumed
    /// token, e-mail mismatch after change). Used for guessing-attack telemetry.</summary>
    public const string EmailVerificationFailed = "EmailVerificationFailed";

    /// <summary>N-4 (Session E, N4-7): the user initiated the strict change-of-e-mail flow.
    /// Payload carries UserId, ClientId, OldEmail, NewEmail (both lowercase), Jti, ExpiresAt.</summary>
    public const string EmailChangeRequested = "EmailChangeRequested";
    /// <summary>N-4 (Session E, N4-7): change-of-e-mail confirmation succeeded — the user's
    /// <c>_users.email</c> was swapped to the new address and <c>UserProps.EmailVerified</c>
    /// was flipped to <c>true</c>.</summary>
    public const string EmailChangeCompleted = "EmailChangeCompleted";
    /// <summary>N-4 (Session E, N4-7): change-of-e-mail confirmation failed (bad / expired /
    /// consumed token, race against another mutation path, address taken on commit).</summary>
    public const string EmailChangeFailed = "EmailChangeFailed";

    // ── authorization (OAuth/OIDC protocol) ──
    public const string TokenIssued = "TokenIssued";
    public const string TokenRevoked = "TokenRevoked";
    /// <summary>H6 (RFC 7662): a token introspection request was processed (active or inactive).</summary>
    public const string TokenIntrospected = "TokenIntrospected";
    public const string AuthorizationGranted = "AuthorizationGranted";
    public const string ConsentGranted = "ConsentGranted";
    public const string ConsentRevoked = "ConsentRevoked";
    public const string AllConsentsRevoked = "AllConsentsRevoked";
    public const string DeviceCodeIssued = "DeviceCodeIssued";
    public const string DeviceCodeVerified = "DeviceCodeVerified";
    public const string DeviceCodeDenied = "DeviceCodeDenied";
    /// <summary>Z6 (RFC 9126): a Pushed Authorization Request was successfully accepted and a request_uri issued.</summary>
    public const string ParRequestAccepted = "ParRequestAccepted";
    /// <summary>Z6 (RFC 9126): a Pushed Authorization Request was rejected (validation, auth, format).</summary>
    public const string ParRequestRejected = "ParRequestRejected";
    /// <summary>Z4 (RFC 9449): an access token was bound to a DPoP confirmation key (cnf.jkt issued).</summary>
    public const string DpopBindingApplied = "DpopBindingApplied";
    /// <summary>Z4 (RFC 9449 §11.1): a DPoP proof JTI replay was detected at the token / resource endpoint.</summary>
    public const string DpopReplayDetected = "DpopReplayDetected";

    // ── admin (management API mutations) ──
    public const string ClientRegistered = "ClientRegistered";
    public const string ClientUpdated = "ClientUpdated";
    public const string ClientDeleted = "ClientDeleted";

    /// <summary>
    /// A new signing key was minted via admin /signing-keys/rotate. Payload carries <c>Kid</c>
    /// and <c>Kind</c>; previously-active keys of the same kind have their <c>IsActive</c> flag
    /// cleared but remain in the JWKS until <see cref="SigningKeyRetired"/> or NotAfter elapses.
    /// </summary>
    public const string SigningKeyRotated = "SigningKeyRotated";

    /// <summary>
    /// A signing key's validity window was ended via admin /signing-keys/{kid}/retire. Payload
    /// carries <c>Kid</c>; the key disappears from JWKS on the next request.
    /// </summary>
    public const string SigningKeyRetired = "SigningKeyRetired";

    /// <summary>
    /// Confidential OAuth client's <c>client_secret</c> was rotated by an administrator.
    /// Audit payload deliberately carries only <c>ClientId</c> — the new plaintext secret
    /// is NEVER persisted in audit logs (only returned once in the HTTP response body).
    /// </summary>
    public const string ClientSecretRotated = "ClientSecretRotated";
    public const string ScopeCreated = "ScopeCreated";
    public const string ScopeUpdated = "ScopeUpdated";
    public const string ScopeDeleted = "ScopeDeleted";
    /// <summary>H5: declarative claim mapper rule was created.</summary>
    public const string ClaimMapperCreated = "ClaimMapperCreated";
    /// <summary>H5: declarative claim mapper rule was updated (props or enabled flag).</summary>
    public const string ClaimMapperUpdated = "ClaimMapperUpdated";
    /// <summary>H5: declarative claim mapper rule was deleted.</summary>
    public const string ClaimMapperDeleted = "ClaimMapperDeleted";
    /// <summary>H5: a reusable Client Scope (mapper bundle) was created.</summary>
    public const string ClaimScopeCreated = "ClaimScopeCreated";
    /// <summary>H5: a Client Scope was updated.</summary>
    public const string ClaimScopeUpdated = "ClaimScopeUpdated";
    /// <summary>H5: a Client Scope was deleted (also cascades all assignments).</summary>
    public const string ClaimScopeDeleted = "ClaimScopeDeleted";
    /// <summary>H5: a Client Scope was assigned to an Application.</summary>
    public const string ClaimScopeAssigned = "ClaimScopeAssigned";
    /// <summary>H5: a Client Scope was unassigned from an Application.</summary>
    public const string ClaimScopeUnassigned = "ClaimScopeUnassigned";
    public const string UserCreated = "UserCreated";
    public const string UserUpdated = "UserUpdated";
    public const string UserDeleted = "UserDeleted";

    /// <summary>N7-3: an admin opened an impersonation session ("view-as" overlay) targeting another user.</summary>
    public const string UserImpersonationStarted = "UserImpersonationStarted";
    /// <summary>N7-3: an admin closed an impersonation session, restoring their own context.</summary>
    public const string UserImpersonationStopped = "UserImpersonationStopped";
    public const string GroupCreated = "GroupCreated";
    public const string GroupUpdated = "GroupUpdated";
    public const string GroupDeleted = "GroupDeleted";
    public const string GroupMoved = "GroupMoved";
    public const string MemberAdded = "MemberAdded";
    public const string MemberUpdated = "MemberUpdated";
    public const string MemberRemoved = "MemberRemoved";

    // ── federation ──
    public const string FederationChallengeInitiated = "FederationChallengeInitiated";
    public const string FederationStateValidationFailed = "FederationStateValidationFailed";
    public const string FederatedUserLoggedIn = "FederatedUserLoggedIn";
    /// <summary>H8 (DoD §4 gap (b)): a logged-in user added a federated identity to their existing account.</summary>
    public const string FederatedIdentityLinked = "FederatedIdentityLinked";
    /// <summary>H8 (DoD §4 gap (b)/(d)): a federated identity was removed from a user account.</summary>
    public const string FederatedIdentityUnlinked = "FederatedIdentityUnlinked";
    /// <summary>H8 (DoD §4 gap (c)): federated callback rejected because the external email matched an existing local user without an explicit link.</summary>
    public const string FederatedEmailConflict = "FederatedEmailConflict";
    /// <summary>H8 (DoD §4 gap (e)): an admin created/updated/deleted an PROPS-stored federation provider.</summary>
    public const string FederationProviderCreated = "FederationProviderCreated";
    public const string FederationProviderUpdated = "FederationProviderUpdated";
    public const string FederationProviderDeleted = "FederationProviderDeleted";

    // ── mfa ──
    public const string MfaEnrolled = "MfaEnrolled";
    public const string MfaDisabled = "MfaDisabled";
    public const string MfaChallengeIssued = "MfaChallengeIssued";
    public const string MfaVerifyFailed = "MfaVerifyFailed";
    public const string MfaRecoveryCodeUsed = "MfaRecoveryCodeUsed";
    /// <summary>MFA: user downloaded a fresh batch of recovery codes (UX wrap over regenerate-recovery).</summary>
    public const string MfaRecoveryCodesDownloaded = "MfaRecoveryCodesDownloaded";
    /// <summary>MFA-3: a WebAuthn credential was registered for the user.</summary>
    public const string MfaWebAuthnRegistered = "MfaWebAuthnRegistered";
    /// <summary>MFA-3: a WebAuthn credential successfully asserted (login or step-up).</summary>
    public const string MfaWebAuthnAsserted = "MfaWebAuthnAsserted";
    /// <summary>MFA-3: a WebAuthn credential was deleted by the user.</summary>
    public const string MfaWebAuthnRevoked = "MfaWebAuthnRevoked";
    /// <summary>MFA-3: detected a sign-counter rollback (possible credential cloning).</summary>
    public const string MfaWebAuthnSignCounterAnomaly = "MfaWebAuthnSignCounterAnomaly";

    // ── scim ──
    public const string ScimUserCreated = "ScimUserCreated";
    public const string ScimUserReplaced = "ScimUserReplaced";
    public const string ScimUserPatched = "ScimUserPatched";
    public const string ScimUserDeleted = "ScimUserDeleted";
    public const string ScimGroupCreated = "ScimGroupCreated";
    public const string ScimGroupReplaced = "ScimGroupReplaced";
    public const string ScimGroupPatched = "ScimGroupPatched";
    public const string ScimGroupDeleted = "ScimGroupDeleted";
    /// <summary>H1 (RFC 7644 §3.7): a SCIM Bulk request was processed (≥ 1 inner operation).</summary>
    public const string ScimBulkProcessed = "ScimBulkProcessed";

    // ── system / housekeeping ──
    public const string SessionRevoked = "SessionRevoked";
    public const string AllSessionsRevoked = "AllSessionsRevoked";
    public const string SessionsPruned = "SessionsPruned";
    /// <summary>W6-0: a single sid (or sub) was published to the backchannel revoked-sids list.</summary>
    public const string SidRevoked = "SidRevoked";
    /// <summary>W6-0: cleanup route purged expired entries from the revoked-sids list.</summary>
    public const string RevokedSidsPruned = "RevokedSidsPruned";
    public const string MfaOtpPruned = "MfaOtpPruned";
    public const string TokenCleanupRan = "TokenCleanupRan";
    public const string TokensPruned = "TokensPruned";
    public const string TokensRevokedByUser = "TokensRevokedByUser";
    /// <summary>N7-4: admin requested a dry-run preview of <see cref="AllSessionsRevoked"/> (no mutation).</summary>
    public const string AllSessionsRevocationPreviewed = "AllSessionsRevocationPreviewed";
    /// <summary>N7-4: admin requested a dry-run preview of <see cref="TokensPruned"/> (no mutation).</summary>
    public const string TokensPrunePreviewed = "TokensPrunePreviewed";

    // ── B.3 role registry ────────────────────────────────────────────────
    public const string RoleCreated = "RoleCreated";
    public const string RoleUpdated = "RoleUpdated";
    public const string RoleDeleted = "RoleDeleted";
    public const string RoleAssignedUser = "RoleAssignedUser";
    public const string RoleUnassignedUser = "RoleUnassignedUser";
    public const string RoleAssignedGroup = "RoleAssignedGroup";
    public const string RoleUnassignedGroup = "RoleUnassignedGroup";
    public const string RoleScopeAttached = "RoleScopeAttached";
    public const string RoleScopeDetached = "RoleScopeDetached";

    // ── W1 webhook subscriptions ─────────────────────────────────────────
    public const string WebhookSubscriptionCreated = "WebhookSubscriptionCreated";
    public const string WebhookSubscriptionUpdated = "WebhookSubscriptionUpdated";
    public const string WebhookSubscriptionDeleted = "WebhookSubscriptionDeleted";
    public const string WebhookSubscriptionSecretRotated = "WebhookSubscriptionSecretRotated";

    /// <summary>
    /// Maps event type to semantic <see cref="IdentityAuditCategories"/> bucket.
    /// Returns <see cref="IdentityAuditCategories.System"/> for unknown types so third-party
    /// emitters remain storable.
    /// </summary>
    public static string CategoryOf(string eventType) => eventType switch
    {
        UserLoggedIn or UserLoggedOut or LoginFailed or PasswordChanged
            or PasswordResetRequested or PasswordResetTokenIssued
            or PasswordResetCompleted or PasswordResetFailed
            or EmailVerificationSent or EmailVerificationCompleted or EmailVerificationFailed
            or EmailChangeRequested or EmailChangeCompleted or EmailChangeFailed
            => IdentityAuditCategories.Authentication,
        TokenIssued or TokenRevoked or TokenIntrospected or AuthorizationGranted or ConsentGranted or ConsentRevoked
            or AllConsentsRevoked or DeviceCodeIssued or DeviceCodeVerified or DeviceCodeDenied
            or ParRequestAccepted or ParRequestRejected or DpopBindingApplied or DpopReplayDetected
            => IdentityAuditCategories.Authorization,
        ClientRegistered or ClientUpdated or ClientDeleted or ClientSecretRotated
            or ScopeCreated or ScopeUpdated
            or ScopeDeleted or UserCreated or UserUpdated or UserDeleted or GroupCreated
            or UserImpersonationStarted or UserImpersonationStopped
            or GroupUpdated or GroupDeleted or GroupMoved or MemberAdded or MemberUpdated
            or MemberRemoved
            or ClaimMapperCreated or ClaimMapperUpdated or ClaimMapperDeleted
            or ClaimScopeCreated or ClaimScopeUpdated or ClaimScopeDeleted
            or ClaimScopeAssigned or ClaimScopeUnassigned
            or FederationProviderCreated or FederationProviderUpdated or FederationProviderDeleted
            or RoleCreated or RoleUpdated or RoleDeleted
            or RoleAssignedUser or RoleUnassignedUser
            or RoleAssignedGroup or RoleUnassignedGroup
            or RoleScopeAttached or RoleScopeDetached
            or WebhookSubscriptionCreated or WebhookSubscriptionUpdated
            or WebhookSubscriptionDeleted or WebhookSubscriptionSecretRotated
            => IdentityAuditCategories.Admin,
        FederationChallengeInitiated or FederationStateValidationFailed or FederatedUserLoggedIn
            or FederatedIdentityLinked or FederatedIdentityUnlinked or FederatedEmailConflict
            => IdentityAuditCategories.Federation,
        MfaEnrolled or MfaDisabled or MfaChallengeIssued or MfaVerifyFailed or MfaRecoveryCodeUsed
            or MfaRecoveryCodesDownloaded
            or MfaWebAuthnRegistered or MfaWebAuthnAsserted or MfaWebAuthnRevoked
            or MfaWebAuthnSignCounterAnomaly
            => IdentityAuditCategories.Mfa,
        ScimUserCreated or ScimUserReplaced or ScimUserPatched or ScimUserDeleted
            or ScimGroupCreated or ScimGroupReplaced or ScimGroupPatched or ScimGroupDeleted
            or ScimBulkProcessed
            => IdentityAuditCategories.Scim,
        _ => IdentityAuditCategories.System
    };
}

/// <summary>Category constants stored in the <c>identity_audit_log.category</c> column.</summary>
public static class IdentityAuditCategories
{
    public const string Authentication = "authentication";
    public const string Authorization = "authorization";
    public const string Admin = "admin";
    public const string Federation = "federation";
    public const string Mfa = "mfa";
    public const string Scim = "scim";
    public const string System = "system";
}
