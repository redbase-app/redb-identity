using System.Security.Claims;
using System.Text.Json;
using redb.Identity.Contracts.Configuration;
using redb.Identity.Contracts.Serialization;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.Http;

namespace redb.Identity.Http.Processors;

/// <summary>
/// N7-1 — per-path scope guard for the management API. Runs after
/// <c>ManagementBearerAuthProcessor</c> has validated the bearer token and stashed
/// <c>identity:management-scopes</c>, and BEFORE <c>StripManagementPrefix</c> so the
/// raw <c>/api/v1/identity/{...}</c> path is still visible.
/// <para>
/// Rules:
/// <list type="bullet">
///   <item>Anonymous short-circuit (<c>identity:management-anonymous</c> set): pass.</item>
///   <item>Token holds <see cref="IdentityScopes.Manage"/>: pass (master admin).</item>
///   <item>Token holds only <see cref="IdentityScopes.Account"/>: pass — the existing
///   <c>RequireSelfOrAdminProcessor</c> downstream enforces self-only access.</item>
///   <item>Token holds <see cref="IdentityScopes.ReadOnly"/>: pass for <c>GET</c>,
///   reject 403 for any mutating method.</item>
///   <item>Otherwise: look up the path prefix in the route table; if the token
///   carries one of the scopes listed for that prefix, pass; else reject 403.</item>
///   <item>Unmapped path with no admin scope: reject 403 (default-deny).</item>
/// </list>
/// </para>
/// </summary>
internal static class GranularScopeGuardProcessor
{
    // Mapping path-prefix → resource (read, write) pair. The guard picks
    // read for GET / HEAD / OPTIONS, write for POST / PUT / PATCH / DELETE.
    // Order matters: longest prefix first wins via OrdinalIgnoreCase StartsWith.
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

        var path = e.In.GetHeader<string>("redbHttp.Path") ?? string.Empty;
        var method = (e.In.GetHeader<string>("redbHttp.Method") ?? "GET").ToUpperInvariant();
        var isMutation = method is not ("GET" or "HEAD" or "OPTIONS");

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

        // Per-path granular check. Pick the read or write scope by method.
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
