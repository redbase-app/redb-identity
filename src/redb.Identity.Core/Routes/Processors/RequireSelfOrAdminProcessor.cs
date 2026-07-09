using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using redb.Identity.Core.Serialization;
using redb.Route.Abstractions;
using redb.Route.Core;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// B8 — IDOR fix. Enforces the «self vs admin» authorization rule on management-API
/// routes that take a <c>userId</c> from the request body.
/// <para>
/// Caller is admitted in one of two cases:
/// <list type="bullet">
///   <item><description>token carries the configured <b>admin</b> scope (typically
///   <c>identity:manage</c>) — may target any user;</description></item>
///   <item><description>token carries the configured <b>self</b> scope (typically
///   <c>identity:account</c>) AND the body <c>userId</c> equals the token's
///   <c>sub</c> claim — may target only the calling user.</description></item>
/// </list>
/// On any other combination (missing scope, mismatched subject, missing userId in body)
/// the request is rejected with HTTP 403 and a single generic error message — never
/// distinguishing «user does not exist» from «not authorized», to avoid information
/// leakage.
/// </para>
/// <para>
/// <b>Internal callers (direct-vm without HTTP).</b> When the upstream
/// <see cref="ManagementBearerAuthProcessor"/> has not run (no
/// <c>identity:management-scopes</c> property on the exchange), this processor treats the
/// call as <i>internal trusted</i> and bypasses the check. direct-vm endpoints are
/// in-process only and not network-reachable; this preserves backwards compatibility
/// with internal service-to-service flows and tests.
/// </para>
/// </summary>
internal sealed class RequireSelfOrAdminProcessor : IProcessor
{
    private readonly string _adminScope;
    private readonly string _accountScope;
    private readonly ILogger _logger;

    public RequireSelfOrAdminProcessor(
        string adminScope,
        string accountScope,
        ILogger? logger = null)
    {
        _adminScope = adminScope ?? throw new ArgumentNullException(nameof(adminScope));
        _accountScope = accountScope ?? throw new ArgumentNullException(nameof(accountScope));
        _logger = logger ?? NullLogger.Instance;
    }

    public Task Process(IExchange exchange, CancellationToken ct = default)
    {
        // Bypass for internal direct-vm callers (no auth context attached). See class docs.
        if (!exchange.Properties.TryGetValue("identity:management-scopes", out var scopesObj)
            || scopesObj is not string[] scopes)
        {
            return Task.CompletedTask;
        }

        var hasAdmin = scopes.Any(s => string.Equals(s, _adminScope, StringComparison.Ordinal));
        if (hasAdmin)
            return Task.CompletedTask; // admin may target any user

        var hasAccount = scopes.Any(s => string.Equals(s, _accountScope, StringComparison.Ordinal));
        if (!hasAccount)
        {
            // Should not happen — ManagementBearerAuthProcessor admitted the token but it
            // carries neither scope. Defensive: deny.
            Reject(exchange);
            return Task.CompletedTask;
        }

        // Self-service path: body userId must match the token's internal user-id.
        // The public sub claim is now a GUID; ManagementBearerAuthProcessor mirrors
        // the bigint _users._id into `identity:management-user-id` from the
        // `redb:user_id` access-token claim. client_credentials tokens won't have
        // it — that's fine, this branch is only reached when the admin scope is
        // absent, and self-service requires an end-user grant.
        var bodyUserId = ExtractUserId(exchange.In.Body);
        var callerUserId = TryGetCallerUserId(exchange);

        if (bodyUserId is null || callerUserId is null || bodyUserId.Value != callerUserId.Value)
        {
            _logger.LogWarning(
                "Self-or-admin authorization denied: callerUserId={CallerUserId}, bodyUserId={BodyUserId}",
                callerUserId, bodyUserId);
            Reject(exchange);
            return Task.CompletedTask;
        }

        return Task.CompletedTask;
    }

    private static long? TryGetCallerUserId(IExchange exchange)
    {
        if (!exchange.Properties.TryGetValue("identity:management-user-id", out var raw))
            return null;

        return raw switch
        {
            long l when l > 0 => l,
            int i when i > 0 => i,
            string s when long.TryParse(s, out var id) && id > 0 => id,
            _ => null
        };
    }

    private static long? ExtractUserId(object? body)
    {
        if (body is not IDictionary<string, object?> dict) return null;
        if (!dict.TryGetValue("userId", out var v) || v is null) return null;
        return v switch
        {
            long l => l,
            int i => i,
            double d => (long)d,
            decimal m => (long)m,
            JsonElement je when je.TryGetInt64(out var jid) => jid,
            string s when long.TryParse(s, out var parsed) => parsed,
            _ => null
        };
    }

    private static void Reject(IExchange exchange)
    {
        // B8: single generic message for all denial reasons (no «existed/not existed» leakage).
        //
        // This is an APPLICATION-level authorization rule (IDOR guard), NOT an RFC 6750
        // OAuth scope check — the 6750 challenge has already been issued upstream by
        // ManagementBearerAuthProcessor. Per current industry practice (RFC 9457,
        // published 2023 to supersede RFC 7807), application-level error responses
        // should use the Problem Details media type `application/problem+json`.
        //
        // OAuth/OIDC endpoints retain the `application/json` envelope mandated by
        // RFC 6749 §5.2 / RFC 6750 §3.1; only generic authz-rule rejections migrate.
        //
        // The `code` extension member preserves the stable machine-readable token
        // ("not_authorized") that existing consumers grep for.
        var problem = new Dictionary<string, object?>
        {
            ["type"] = "https://redb.local/problems/authorization-denied",
            ["title"] = "Forbidden",
            ["status"] = 403,
            ["detail"] = "The access token does not authorize the requested operation.",
            ["code"] = "not_authorized"
        };

        // Serialize through the locked Problem profile facade. This produces the same
        // wire format a registry lookup for "application/problem+json" would return
        // (see IdentityCodecProfilesConfigurator); we skip the registry round-trip
        // here because this processor has no reference to the route context and the
        // Problem profile is an Identity-owned, RFC-locked artifact.
        var body = IdentityCodecProfiles.Problem.Serialize(problem);
        exchange.Out = new Message(body);
        // Core-level content type keeps the value transport-agnostic for Rabbit/Kafka façades.
        exchange.Out.ContentType = IdentityCodecProfiles.ProblemMediaType;
        exchange.Out.Headers["redbHttp.ResponseCode"] = 403;
        exchange.Out.Headers["redbHttp.ResponseContentType"] = IdentityCodecProfiles.ProblemMediaType;
        exchange.Exception = new UnauthorizedAccessException("Self-or-admin authorization denied.");
        exchange.ExceptionHandled = true;
        exchange.Stop();
    }
}
