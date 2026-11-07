using redb.Core.Models.Entities;
using redb.Identity.Contracts.Sessions;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.RedbCore.Extensions;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// H3-SSO (v1.0 DoD §6 scoped-subset): self-service session endpoint.
/// Caller targets <b>only</b> their own sessions — userId is derived from the
/// authenticated token subject (<c>identity:management-subject</c>), never from the
/// request body. Supports four operations:
/// <list type="bullet">
///   <item><description><c>list</c> — list caller's active sessions.</description></item>
///   <item><description><c>revoke</c> — revoke a single session by id; verifies the target
///   session belongs to the caller before revoking.</description></item>
///   <item><description><c>revoke-current</c> — revoke the session the caller's access
///   token was issued for. The session id is taken from the <c>sid</c> claim carried
///   by the bearer token (surfaced as <c>identity:management-sid</c>); the request body
///   is ignored. Returns 400 if the token has no <c>sid</c> claim (e.g. client_credentials
///   grant or other non-session-backed tokens).</description></item>
///   <item><description><c>revoke-others</c> — revoke all of the caller's sessions except
///   the one identified by the <c>sid</c> claim. If <c>sid</c> is absent, all sessions
///   are revoked. Used by the account console "Sign out other devices" action.</description></item>
/// </list>
/// Unlike <see cref="SessionManagementProcessor"/>, this processor does NOT support
/// admin-scoped <c>revoke-all</c> / <c>logout</c> for arbitrary users.
/// <para>
/// <b>Authorization.</b> The upstream <see cref="ManagementBearerAuthProcessor"/>
/// validates the Bearer token and populates <c>identity:management-subject</c> with
/// the <c>sub</c> claim. This processor requires that property to be present and
/// numerically parseable; otherwise it rejects with 401. For non-numeric subjects
/// (e.g. UUID-issuing hosts) the self-service path is unavailable by design —
/// callers must use the admin scope.
/// </para>
/// <para>
/// <b>Revoke ownership check.</b> Before revoking a session we load it and verify
/// that <c>session.key == caller</c>. A caller attempting to revoke another user's
/// session receives 404 (not 403) to avoid leaking existence of other sessions.
/// </para>
/// </summary>
internal sealed class MeSessionsProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;

    public MeSessionsProcessor(IRouteContext context, string? redbName = null)
    {
        _context = context;
        _redbName = redbName;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var callerId = TryGetCallerUserId(exchange);
        if (callerId is null)
        {
            Reject(exchange, 401, "invalid_token",
                $"The access token does not carry a numeric subject claim required for self-service session APIs (got subject={MeProcessorHelpers.GetRawCallerSubject(exchange) ?? "<null>"}).");
            return;
        }

        var operation = exchange.In.GetHeader<string>("operation")
            ?? throw new InvalidOperationException("Missing 'operation' header");

        // Pre-validate revoke-current's sid precondition BEFORE touching IRouteContext,
        // so tokens without a session binding are rejected cheaply and the unit-test
        // surface stays free of redb-service wiring.
        // For revoke-others the sid is optional — if absent all sessions are revoked.
        long? currentSessionId = null;
        if (operation is "revoke-current" or "revoke-others")
        {
            currentSessionId = TryGetSessionId(exchange);
            if (currentSessionId is null && operation == "revoke-current")
            {
                Reject(exchange, 400, "sid_unavailable",
                    "The access token has no session binding (sid claim). revoke-current is only available for tokens issued via the OIDC session flow.");
                return;
            }
        }

        var redb = _context.GetRedbService(_redbName!, exchange);
        var session = new SessionService(redb);

        switch (operation)
        {
            case "list":
                await List(session, exchange, callerId.Value, ct).ConfigureAwait(false);
                break;
            case "revoke":
                await Revoke(session, redb, exchange, callerId.Value, ct).ConfigureAwait(false);
                break;
            case "revoke-current":
                await RevokeIfOwned(session, redb, exchange, callerId.Value,
                    currentSessionId!.Value, selfCurrent: true, ct).ConfigureAwait(false);
                break;
            case "revoke-others":
                await RevokeOthers(session, exchange, callerId.Value, currentSessionId, ct).ConfigureAwait(false);
                break;
            default:
                Reject(exchange, 400, "invalid_operation", $"Unknown operation: {operation}");
                break;
        }
    }

    private static async Task List(SessionService session, IExchange exchange, long callerId, CancellationToken ct)
    {
        var sessions = await session.ListAsync(callerId, ct).ConfigureAwait(false);
        exchange.Out ??= new Message();
        exchange.Out.Body = sessions.Select(s => new SessionResponse
        {
            SessionId = s.SessionId,
            UserId = s.UserId,
            ApplicationId = s.ApplicationObjectId,
            ClientId = s.ClientId,
            ApplicationName = s.ApplicationName,
            Status = s.Status,
            CreatedAt = s.CreatedAt,
            IpAddress = s.IpAddress,
            UserAgent = s.UserAgent,
            DeviceLabel = s.DeviceLabel
        }).ToList();
    }

    private static async Task Revoke(
        SessionService session,
        redb.Core.IRedbService redb,
        IExchange exchange,
        long callerId,
        CancellationToken ct)
    {
        var dict = exchange.In.Body as Dictionary<string, object?>
            ?? throw new InvalidOperationException("Body is required");
        var sessionId = IdentityProcessorHelpers.ExtractLong(dict, "sessionId")
            ?? throw new InvalidOperationException("sessionId is required");

        await RevokeIfOwned(session, redb, exchange, callerId, sessionId, selfCurrent: false, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Revokes all of the caller's sessions except <paramref name="exceptSessionId"/>.
    /// When <paramref name="exceptSessionId"/> is <c>null</c> (token has no <c>sid</c>
    /// claim) all sessions are revoked.
    /// </summary>
    private static async Task RevokeOthers(
        SessionService session,
        IExchange exchange,
        long callerId,
        long? exceptSessionId,
        CancellationToken ct)
    {
        var sessions = await session.ListAsync(callerId, ct).ConfigureAwait(false);
        var revoked = 0;
        foreach (var s in sessions)
        {
            if (exceptSessionId is not null && s.SessionId == exceptSessionId.Value)
                continue;
            revoked += await session.RevokeAsync(s.SessionId, ct).ConfigureAwait(false);
        }

        exchange.Out ??= new Message();
        exchange.Out.Body = new Dictionary<string, object?>
        {
            ["success"] = true,
            ["revoked"] = revoked
        };
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.SessionRevoked;
        exchange.Properties["identity-event-data"] = new
        {
            SelfService = true,
            SelfCurrent = false,
            Count = revoked
        };
    }

    /// <summary>
    /// Extracts the session id from the <c>sid</c> claim surfaced by
    /// <see cref="ManagementBearerAuthProcessor"/>. Returns <c>null</c> when the
    /// claim is absent (e.g. client_credentials grant) or not a positive integer.
    /// </summary>
    private static long? TryGetSessionId(IExchange exchange)
    {
        if (!exchange.Properties.TryGetValue("identity:management-sid", out var raw)
            || raw is not string sidStr
            || string.IsNullOrEmpty(sidStr))
        {
            return null;
        }

        return long.TryParse(sidStr, out var id) && id > 0 ? id : null;
    }

    private static async Task RevokeIfOwned(
        SessionService session,
        redb.Core.IRedbService redb,
        IExchange exchange,
        long callerId,
        long sessionId,
        bool selfCurrent,
        CancellationToken ct)
    {
        // Ownership check: load the session and verify it belongs to the caller.
        // 404 (not 403) on mismatch/not-found — callers must not learn about other
        // users' sessions by probing IDs.
        var target = await redb.LoadAsync<SessionProps>(sessionId).ConfigureAwait(false);
        if (target is null || target.key != callerId)
        {
            Reject(exchange, 404, "not_found", "Session not found.");
            return;
        }

        var revoked = await session.RevokeAsync(sessionId, ct).ConfigureAwait(false);
        exchange.Out ??= new Message();
        exchange.Out.Body = new Dictionary<string, object?>
        {
            ["success"] = true,
            ["revoked"] = revoked
        };
        // Emit audit event via the existing WireTap on the route.
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.SessionRevoked;
        exchange.Properties["identity-event-data"] = new
        {
            SessionId = sessionId,
            SelfService = true,
            SelfCurrent = selfCurrent
        };
    }

    /// <summary>
    /// Extracts the internal numeric caller id from <c>identity:management-user-id</c>
    /// (mirrored from the <c>redb:user_id</c> access-token claim by
    /// <see cref="ManagementBearerAuthProcessor"/>; the public <c>sub</c> is now a GUID).
    /// </summary>
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

    private static void Reject(IExchange exchange, int statusCode, string error, string description)
    {
        exchange.Out = new Message(new Dictionary<string, object?>
        {
            ["error"] = error,
            ["error_description"] = description
        });
        exchange.Out.Headers["redbHttp.ResponseCode"] = statusCode;
        exchange.Exception = new InvalidOperationException(description);
        exchange.ExceptionHandled = true;
        exchange.Stop();
    }
}
