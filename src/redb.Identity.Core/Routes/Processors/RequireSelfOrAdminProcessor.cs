using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using redb.Route.Abstractions;

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
/// On any other combination (missing scope, mismatched subject, missing userId in body,
/// no management context at all) the request is rejected with HTTP 403 and a single
/// generic error message — never distinguishing «user does not exist» from «not
/// authorized», to avoid information leakage.
/// </para>
/// <para>
/// <b>No management context is a refusal, not a bypass.</b> This processor used to admit an
/// exchange without <c>identity:management-scopes</c> as an "internal trusted" caller, on the
/// reasoning that <c>direct-vm</c> is not network-reachable. In a Tsak worker the <c>direct-vm</c>
/// registry is shared by every module in the process, so that reasoning granted any module
/// admin rights over users' MFA. The gate at the route entrance
/// (<see cref="RequireManagementContextProcessor"/>) refuses such exchanges first; this processor
/// refuses them too, so the rule holds even if it is ever placed on a route without the gate.
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
        if (!exchange.Properties.TryGetValue(RequireManagementContextProcessor.ScopesProperty, out var scopesObj)
            || scopesObj is not string[] scopes)
        {
            // Nobody authenticated this caller. Not a trusted internal one — see the class docs.
            _logger.LogWarning(
                "Self-or-admin authorization denied: no management context on the exchange (route={RouteId})",
                exchange.RouteId);
            Reject(exchange);
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

    // B8: one generic message for every denial reason (no «existed/not existed» leakage);
    // the shape itself lives in ManagementProblem so every gate on the surface answers alike.
    private static void Reject(IExchange exchange)
        => ManagementProblem.Forbidden(exchange, "The access token does not authorize the requested operation.");
}
