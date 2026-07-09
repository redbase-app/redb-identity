using redb.Identity.Core.Models;
using redb.Identity.DataProtection;

namespace redb.Identity.Core.Hosting;

/// <summary>
/// Authoritative list of all PROPS schemas managed by redb.Identity.
/// Single source of truth for schema bootstrap (<see cref="Module.IdentitySchemaInitListener"/>)
/// and test fixtures. External modules extending Identity with their own <c>*Props</c> can add
/// types via <see cref="Register{TProps}"/> BEFORE the route context starts.
/// </summary>
public static class IdentitySchemaRegistry
{
    private static readonly List<Type> _types =
    [
        typeof(UserProps),
        typeof(MfaProps),
        typeof(SessionProps),
        typeof(ApplicationProps),
        typeof(AuthorizationProps),
        typeof(ScopeProps),
        typeof(TokenProps),
        typeof(GroupProps),
        typeof(GroupMemberProps),
        typeof(IdempotencyRecordProps),
        typeof(DataProtectionKeyProps),
        typeof(SigningKeyProps),
        typeof(MfaOtpProps),
        typeof(WebAuthnConsumedChallengeProps),
        typeof(DpopConsumedJtiProps),
        // Session lifecycle: revoked-sid blacklist for OIDC back-channel logout +
        // single-logout enforcement. Cleanup processor queries by ExpiresAt < now()
        // — scheme MUST be registered or the Quartz cleanup tick throws every run.
        typeof(RevokedSidProps),
        // R1: AuditEventProps removed — audit moved to the flat relational
        // identity_audit_log table managed by IdentityAuditLogTableInitListener.
        typeof(PasswordHistoryProps),
        // H5 (DoD §5): declarative claim mapping rules + reusable Client Scopes + assignments.
        typeof(ClaimMapperProps),
        typeof(ClaimScopeProps),
        typeof(ClaimScopeAssignmentProps),
        // S2: claim schema (required/type/regex) with global + per-application scope.
        typeof(ClaimDefinitionProps),
        // B.3: first-class Roles registry — audience-scoped (organization /
        // application) buckets assignable to users directly + to groups
        // transitively. Effective role set resolved at token issuance.
        typeof(RoleProps),
        typeof(UserRoleAssignmentProps),
        typeof(GroupRoleAssignmentProps),
        typeof(RoleScopeAssignmentProps),
        // W1: outbound webhook subscriptions — fan-out for the events route.
        typeof(WebhookSubscriptionProps),
        // H8 (DoD §4): per-user federated identity links + PROPS-stored federation provider configs.
        typeof(FederatedIdentityProps),
        typeof(FederationProviderProps),
        // B1: bootstrap / system flag store (bare RedbObject — Props intentionally empty).
        typeof(IdentitySystemFlagProps),
    ];

    /// <summary>
    /// All Props types to be synchronized with PROPS on Identity startup.
    /// </summary>
    public static IReadOnlyList<Type> Types
    {
        get
        {
            lock (_types) return _types.ToArray();
        }
    }

    /// <summary>
    /// Registers an additional <c>*Props</c> type to be provisioned alongside the
    /// built-in Identity schemas. Must be called BEFORE the Identity route context starts
    /// (typically from a host-side <c>AddRedbIdentityServer</c> follow-up, or a sibling
    /// module's <c>InitRoute.main</c> that executes earlier in the load order).
    /// </summary>
    public static void Register<TProps>() where TProps : class
    {
        lock (_types)
        {
            if (!_types.Contains(typeof(TProps)))
                _types.Add(typeof(TProps));
        }
    }
}
