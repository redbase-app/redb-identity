namespace redb.Identity.Contracts.Configuration;

/// <summary>
/// Central registry of OAuth scopes recognised by the management API.
///
/// <para>
/// Scope strings encode <c>resource:action</c> directly — RFC 6749 §3.3 stays the
/// transport, but each scope identifies WHICH admin surface it grants access to
/// and AT WHICH level (read vs write). Operators see a tree-shaped picker on
/// <c>/admin/roles/{id}</c> by parsing the colon; the token claim remains a flat
/// space-separated string, fully compatible with every OIDC consumer.
/// </para>
///
/// <para>
/// Action semantics (Option B — preview.1):
/// <list type="bullet">
///   <item><c>:read</c> — GET on the resource's collection / item.</item>
///   <item><c>:write</c> — POST / PUT / PATCH / DELETE. Includes DELETE on
///     purpose; granting "manage" semantics with two levels (read / write)
///     keeps the catalogue compact while still meaningfully separating
///     audit-reader machines from mutation-capable ones.</item>
/// </list>
/// </para>
///
/// <para>
/// Authorisation precedence at the management gate (<c>GranularScopeGuardProcessor</c>):
/// <list type="number">
///   <item>Token holds <see cref="Manage"/>: pass (master admin).</item>
///   <item>Token holds <see cref="Account"/> and path is <c>/me/*</c>: pass.</item>
///   <item>Token holds <see cref="ReadOnly"/> and method is GET-class: pass.</item>
///   <item>Token holds the resource's <c>:read</c> for GET, or <c>:write</c>
///     for mutations: pass.</item>
///   <item>Otherwise: 403 insufficient_scope.</item>
/// </list>
/// </para>
/// </summary>
public static class IdentityScopes
{
    // ── Universal scopes ──────────────────────────────────────────────────

    /// <summary>Full administrative access — short-circuits the granular gate.</summary>
    public const string Manage = "identity:manage";

    /// <summary>Self-service — token may only target the owning user's <c>/me/*</c> endpoints.</summary>
    public const string Account = "identity:account";

    /// <summary>Read-only admin — GETs across every management endpoint succeed; mutations rejected.</summary>
    public const string ReadOnly = "identity:read";

    // ── Resource × action (read / write) ──────────────────────────────────
    //
    // Naming: 'identity:<resource>:<action>'. Resources are the noun the URL
    // segment shows (/users → users, /federation-providers → federation, etc.);
    // actions are 'read' (GET) and 'write' (everything else).

    public const string UsersRead             = "identity:users:read";
    public const string UsersWrite            = "identity:users:write";

    public const string GroupsRead            = "identity:groups:read";
    public const string GroupsWrite           = "identity:groups:write";

    public const string ConsentsRead          = "identity:consents:read";
    public const string ConsentsWrite         = "identity:consents:write";

    public const string MfaRead               = "identity:mfa:read";
    public const string MfaWrite              = "identity:mfa:write";

    public const string ApplicationsRead      = "identity:applications:read";
    public const string ApplicationsWrite     = "identity:applications:write";

    public const string ScopesRead            = "identity:scopes:read";
    public const string ScopesWrite           = "identity:scopes:write";

    public const string RolesRead             = "identity:roles:read";
    public const string RolesWrite            = "identity:roles:write";

    /// <summary>Covers claim-mappers + claim-definitions + claim-scopes (the entire claims surface).</summary>
    public const string ClaimsRead            = "identity:claims:read";
    public const string ClaimsWrite           = "identity:claims:write";

    public const string FederationRead        = "identity:federation:read";
    public const string FederationWrite       = "identity:federation:write";

    public const string WebhooksRead          = "identity:webhooks:read";
    public const string WebhooksWrite         = "identity:webhooks:write";

    public const string SigningKeysRead       = "identity:signing-keys:read";
    /// <summary>Includes the rotate operation — rotation is a write.</summary>
    public const string SigningKeysWrite      = "identity:signing-keys:write";

    /// <summary>Read sessions (incl. across users) — backs the admin sessions browse.</summary>
    public const string SessionsRead          = "identity:sessions:read";
    /// <summary>Revoke sessions and the revoked-sid list — revoke is a write.</summary>
    public const string SessionsWrite         = "identity:sessions:write";

    /// <summary>Read OAuth tokens (admin browse / introspect).</summary>
    public const string TokensRead            = "identity:tokens:read";
    /// <summary>Revoke / prune tokens.</summary>
    public const string TokensWrite           = "identity:tokens:write";

    /// <summary>Read access to the audit log.</summary>
    public const string AuditRead             = "identity:audit:read";

    /// <summary>Impersonate-as endpoint (RFC 8693 token exchange with <c>act</c> claim).</summary>
    public const string Impersonate           = "identity:impersonate";

    // ── Composite arrays ──────────────────────────────────────────────────

    /// <summary>Every scope registered by the identity server. OpenIddict
    /// <c>server.RegisterScopes(...)</c> seed source.</summary>
    public static readonly string[] All =
    {
        Manage, Account, ReadOnly,
        UsersRead, UsersWrite,
        GroupsRead, GroupsWrite,
        ConsentsRead, ConsentsWrite,
        MfaRead, MfaWrite,
        ApplicationsRead, ApplicationsWrite,
        ScopesRead, ScopesWrite,
        RolesRead, RolesWrite,
        ClaimsRead, ClaimsWrite,
        FederationRead, FederationWrite,
        WebhooksRead, WebhooksWrite,
        SigningKeysRead, SigningKeysWrite,
        SessionsRead, SessionsWrite,
        TokensRead, TokensWrite,
        AuditRead,
        Impersonate,
    };

    /// <summary>Granular admin scopes (everything except <see cref="Manage"/> /
    /// <see cref="Account"/>). The bearer-auth processor's any-of acceptable set.</summary>
    public static readonly string[] GranularAdmin =
    {
        ReadOnly,
        UsersRead, UsersWrite,
        GroupsRead, GroupsWrite,
        ConsentsRead, ConsentsWrite,
        MfaRead, MfaWrite,
        ApplicationsRead, ApplicationsWrite,
        ScopesRead, ScopesWrite,
        RolesRead, RolesWrite,
        ClaimsRead, ClaimsWrite,
        FederationRead, FederationWrite,
        WebhooksRead, WebhooksWrite,
        SigningKeysRead, SigningKeysWrite,
        SessionsRead, SessionsWrite,
        TokensRead, TokensWrite,
        AuditRead,
        Impersonate,
    };
}
