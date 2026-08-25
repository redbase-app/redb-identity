using System.Text.Json;
using redb.Identity.Contracts.Configuration;
using redb.Identity.Contracts.Serialization;
using redb.Route.Abstractions;
using redb.Route.Core;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// Ф5 — the granular scope check for the management surface, behind
/// <c>direct-vm://identity-authz-check</c>. Runs after the authentication step has validated the bearer
/// token and stashed <c>identity:management-scopes</c>.
/// <para>
/// This table used to live in the HTTP facade. It is here now because a second transport was about to
/// need it, and the failure mode of two copies is not that they disagree loudly — it is that one of them
/// quietly grants more than the other, on the surface where that matters most. Moved verbatim: same
/// order, same write-implies-read rule, same account branch, same default-deny, same messages. A refusal
/// worded differently would have broken the HTTP negative matrix, and rewriting those expectations is
/// exactly how a regression net gets cut.
/// </para>
/// <para>
/// Inputs, all transport-neutral:
/// <list type="bullet">
///   <item><c>identity:authz-resource</c> — canonical resource identifier. The identifiers are the
///   management paths (<c>/api/v1/identity/users</c>, …) because that is what they have always been
///   called; HTTP passes its own path unchanged and other transports map their addresses onto the same
///   names.</item>
///   <item><c>identity:authz-action</c> — <c>read</c> or <c>write</c>.</item>
///   <item><c>identity:management-scopes</c> — from the authentication step.</item>
///   <item><c>identity:management-anonymous</c> — short-circuit for routes that are open by design.</item>
/// </list>
/// </para>
/// </summary>
internal sealed class AuthorizationCheckProcessor : IProcessor
{
    /// <summary>Exchange property naming the resource being reached.</summary>
    public const string ResourceProperty = "identity:authz-resource";

    /// <summary>Exchange property naming the action: <c>read</c> or <c>write</c>.</summary>
    public const string ActionProperty = "identity:authz-action";

    // Mapping resource-prefix → (read, write) pair. Order matters: longest prefix first wins via
    // OrdinalIgnoreCase StartsWith. Moved verbatim from GranularScopeGuardProcessor.
    private static readonly (string Prefix, string Read, string Write)[] Map =
    {
        ("/api/v1/identity/audit",                IdentityScopes.AuditRead,        IdentityScopes.AuditRead),
        ("/api/v1/identity/users",                IdentityScopes.UsersRead,        IdentityScopes.UsersWrite),
        ("/api/v1/identity/groups",               IdentityScopes.GroupsRead,       IdentityScopes.GroupsWrite),
        ("/api/v1/identity/consents",             IdentityScopes.ConsentsRead,     IdentityScopes.ConsentsWrite),
        ("/api/v1/identity/mfa",                  IdentityScopes.MfaRead,          IdentityScopes.MfaWrite),
        ("/api/v1/identity/sessions",             IdentityScopes.SessionsRead,     IdentityScopes.SessionsWrite),
        ("/api/v1/identity/tokens",               IdentityScopes.TokensRead,       IdentityScopes.TokensWrite),
        ("/api/v1/identity/revoked-sids",         IdentityScopes.SessionsRead,     IdentityScopes.SessionsWrite),
        ("/api/v1/identity/applications",         IdentityScopes.ApplicationsRead, IdentityScopes.ApplicationsWrite),
        ("/api/v1/identity/scopes",               IdentityScopes.ScopesRead,       IdentityScopes.ScopesWrite),
        ("/api/v1/identity/claim-mappers",        IdentityScopes.ClaimsRead,       IdentityScopes.ClaimsWrite),
        ("/api/v1/identity/claim-scopes",         IdentityScopes.ClaimsRead,       IdentityScopes.ClaimsWrite),
        ("/api/v1/identity/claim-definitions",    IdentityScopes.ClaimsRead,       IdentityScopes.ClaimsWrite),
        ("/api/v1/identity/roles",                IdentityScopes.RolesRead,        IdentityScopes.RolesWrite),
        ("/api/v1/identity/webhooks",             IdentityScopes.WebhooksRead,     IdentityScopes.WebhooksWrite),
        ("/api/v1/identity/federation-providers", IdentityScopes.FederationRead,   IdentityScopes.FederationWrite),
        ("/api/v1/identity/signing-keys",         IdentityScopes.SigningKeysRead,  IdentityScopes.SigningKeysWrite),
        ("/api/v1/identity/admin/impersonate",    IdentityScopes.Impersonate,      IdentityScopes.Impersonate),
        // /me/* paths are NOT mapped here — they are reached via Account scope and
        // the self-service downstream check, which both already pass the gate above.
    };

    /// <inheritdoc />
    public Task Process(IExchange exchange, CancellationToken ct = default) => Enforce(exchange, ct);

    internal static Task Enforce(IExchange e, CancellationToken ct)
    {
        if (e.Properties.TryGetValue("identity:management-anonymous", out var anon) && anon is true)
            return Task.CompletedTask;

        if (!e.Properties.TryGetValue("identity:management-scopes", out var scopesObj)
            || scopesObj is not string[] scopes
            || scopes.Length == 0)
        {
            // Bearer-auth must have populated scopes by this point. Defensive deny.
            Reject(e, 403, "insufficient_scope", "Access token carries no scopes.");
            return Task.CompletedTask;
        }

        // Master admin scope — bypass.
        if (Array.IndexOf(scopes, IdentityScopes.Manage) >= 0)
            return Task.CompletedTask;

        var path = ReadResource(e);
        var isMutation = ReadAction(e) == "write";

        // ReadOnly admin: any admin path, GET-class only.
        if (Array.IndexOf(scopes, IdentityScopes.ReadOnly) >= 0 && !isMutation)
            return Task.CompletedTask;

        // /me/* and explicitly anonymous self-service paths are admitted on Account scope
        // alone — RequireSelfOrAdminProcessor enforces self-only further down.
        if (Array.IndexOf(scopes, IdentityScopes.Account) >= 0)
        {
            if (path.StartsWith("/api/v1/identity/me", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/api/v1/identity/account/", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/api/v1/identity/password/", StringComparison.OrdinalIgnoreCase))
            {
                return Task.CompletedTask;
            }
        }

        // Per-path granular check. Pick the read or write scope by action.
        // Write implies read by RBAC convention — if the caller holds the
        // surface's :write, GET on the same surface is admitted without
        // also requiring :read. The inverse never holds (read does NOT
        // imply write).
        foreach (var (prefix, read, write) in Map)
        {
            if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                continue;

            if (isMutation)
            {
                if (Array.IndexOf(scopes, write) >= 0)
                    return Task.CompletedTask;
                Reject(e, 403, "insufficient_scope",
                    $"This endpoint requires the '{write}' scope (received: {string.Join(", ", scopes)}).");
                return Task.CompletedTask;
            }

            // GET-class — accept either :read OR :write (write implies read).
            if (Array.IndexOf(scopes, read) >= 0 || Array.IndexOf(scopes, write) >= 0)
                return Task.CompletedTask;

            Reject(e, 403, "insufficient_scope",
                $"This endpoint requires the '{read}' scope (or '{write}', which implies read) (received: {string.Join(", ", scopes)}).");
            return Task.CompletedTask;
        }

        // Unmapped admin path with no Manage / ReadOnly: default-deny.
        Reject(e, 403, "insufficient_scope",
            $"Access token does not carry a scope authorising '{path}'.");
        return Task.CompletedTask;
    }

    /// <summary>
    /// The resource the caller is reaching. A transport states it explicitly; HTTP does not have to,
    /// because its path already is the canonical identifier and passing it twice would let the two drift.
    /// </summary>
    private static string ReadResource(IExchange e)
    {
        if (e.Properties.TryGetValue(ResourceProperty, out var resource) && resource is string named
            && !string.IsNullOrEmpty(named))
        {
            return named;
        }

        return e.In.GetHeader<string>("redbHttp.Path") ?? string.Empty;
    }

    /// <summary>
    /// Read or write. Stated explicitly by transports that have no HTTP method; derived from the method
    /// otherwise, with the same GET/HEAD/OPTIONS split as before.
    /// </summary>
    private static string ReadAction(IExchange e)
    {
        if (e.Properties.TryGetValue(ActionProperty, out var action) && action is string named
            && !string.IsNullOrEmpty(named))
        {
            return named.Equals("write", StringComparison.OrdinalIgnoreCase) ? "write" : "read";
        }

        var method = (e.In.GetHeader<string>("redbHttp.Method") ?? "GET").ToUpperInvariant();
        return method is "GET" or "HEAD" or "OPTIONS" ? "read" : "write";
    }

    private static void Reject(IExchange exchange, int statusCode, string error, string description)
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object?>
        {
            ["error"] = error,
            ["error_description"] = description
        }, IdentityWireProfiles.OAuthOptions);
        exchange.Out = new Message(body);
        exchange.Out.ContentType = "application/json";
        exchange.Out.Headers["redbHttp.ResponseCode"] = statusCode;
        exchange.Out.Headers["redbHttp.ResponseContentType"] = "application/json";
        var safeDesc = description.Replace("\\", "\\\\").Replace("\"", "\\\"");
        var safeError = error.Replace("\\", "\\\\").Replace("\"", "\\\"");
        exchange.Out.Headers["WWW-Authenticate"] =
            $"Bearer realm=\"identity\", error=\"{safeError}\", error_description=\"{safeDesc}\"";
        exchange.Exception = new UnauthorizedAccessException(description);
        exchange.ExceptionHandled = true;
        exchange.Stop();
    }
}
