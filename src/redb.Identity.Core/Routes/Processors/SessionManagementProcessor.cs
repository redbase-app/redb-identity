using redb.Core;
using redb.Identity.Contracts.Sessions;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.RedbCore.Extensions;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// Management processor for user sessions.
/// Dispatches on the "operation" header: list, revoke, revoke-all, logout.
/// </summary>
internal sealed class SessionManagementProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;

    public SessionManagementProcessor(IRouteContext context, string? redbName = null)
    {
        _context = context;
        _redbName = redbName;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var redb = _context.GetRedbService(_redbName!, exchange);
        var session = new SessionService(redb);
        var operation = exchange.In.GetHeader<string>("operation")
            ?? throw new InvalidOperationException("Missing 'operation' header");

        switch (operation)
        {
            case "list":
                await List(session, redb, exchange, ct);
                break;
            case "list-all":
                await ListAll(session, redb, exchange, ct);
                break;
            case "revoke":
                await Revoke(session, exchange, ct);
                break;
            case "revoke-all":
                await RevokeAll(session, exchange, ct);
                break;
            case "logout":
                await Logout(session, exchange, ct);
                break;
            default:
                exchange.Out ??= new redb.Route.Core.Message();
                exchange.Out.Body = new { error = "invalid_operation", error_description = $"Unknown operation: {operation}" };
                break;
        }
    }

    private static async Task List(SessionService session, IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        var userId = IdentityProcessorHelpers.ExtractRequiredLong(exchange, "userId");
        var sessions = await session.ListAsync(userId, ct);
        var loginLookup = await ResolveLoginsAsync(redb, sessions.Select(s => s.UserId), ct);
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = sessions.Select(s => Map(s, loginLookup)).ToList();
    }

    /// <summary>
    /// Admin-wide browse of active sessions across all users. Paginated;
    /// powers the /admin/sessions default view so the operator sees what's
    /// alive without first having to pick a target user.
    /// </summary>
    private static async Task ListAll(SessionService session, IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        var dict = exchange.In.Body as Dictionary<string, object?>;
        var offset = (int)(IdentityProcessorHelpers.ExtractLong(dict ?? new(), "offset") ?? 0);
        var count = (int)(IdentityProcessorHelpers.ExtractLong(dict ?? new(), "count") ?? 25);
        var (items, total) = await session.ListAllActiveAsync(offset, count, ct);
        var loginLookup = await ResolveLoginsAsync(redb, items.Select(s => s.UserId), ct);
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new Dictionary<string, object?>
        {
            ["items"] = items.Select(s => Map(s, loginLookup)).ToList(),
            ["total"] = total,
            ["offset"] = offset,
            ["count"] = count
        };
    }

    private static SessionResponse Map(SessionService.SessionInfo s, Dictionary<long, string?> loginLookup) => new()
    {
        SessionId = s.SessionId,
        UserId = s.UserId,
        UserLogin = loginLookup.GetValueOrDefault(s.UserId),
        ApplicationId = s.ApplicationObjectId,
        ClientId = s.ClientId,
        ApplicationName = s.ApplicationName,
        Status = s.Status,
        CreatedAt = s.CreatedAt,
        IpAddress = s.IpAddress,
        UserAgent = s.UserAgent,
        DeviceLabel = s.DeviceLabel,
        LastAccessedAt = s.LastAccessedAt,
        LastAccessedBy = s.LastAccessedBy
    };

    /// <summary>
    /// Bulk-resolve user logins for a session set. Same pattern as
    /// RoleManagementProcessor.ListAssignees — per-id GetUserByIdAsync via
    /// the dedicated UserProvider entry point, in parallel, bounded by the
    /// page size. Correct at any user-count.
    /// </summary>
    private static async Task<Dictionary<long, string?>> ResolveLoginsAsync(
        IRedbService redb, IEnumerable<long> userIds, CancellationToken ct)
    {
        var distinct = userIds.Where(id => id > 0).Distinct().ToArray();
        if (distinct.Length == 0) return new Dictionary<long, string?>();
        var lookups = distinct.Select(async id =>
        {
            try { return (id, login: (await redb.UserProvider.GetUserByIdAsync(id).ConfigureAwait(false))?.Login); }
            catch { return (id, login: (string?)null); }
        });
        var pairs = await Task.WhenAll(lookups).ConfigureAwait(false);
        var map = new Dictionary<long, string?>(pairs.Length);
        foreach (var (id, login) in pairs) map[id] = login;
        return map;
    }

    private static async Task Revoke(SessionService session, IExchange exchange, CancellationToken ct)
    {
        var dict = exchange.In.Body as Dictionary<string, object?>
            ?? throw new InvalidOperationException("Body is required");
        var sessionId = IdentityProcessorHelpers.ExtractLong(dict, "sessionId")
            ?? throw new InvalidOperationException("sessionId is required");
        var revoked = await session.RevokeAsync(sessionId, ct);
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new Dictionary<string, object?> { ["success"] = true, ["revoked"] = revoked };
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.SessionRevoked;
        exchange.Properties["identity-event-data"] = new { SessionId = sessionId };
    }

    private static async Task RevokeAll(SessionService session, IExchange exchange, CancellationToken ct)
    {
        var userId = IdentityProcessorHelpers.ExtractRequiredLong(exchange, "userId");
        var dryRun = ExtractDryRun(exchange);
        if (dryRun)
        {
            var preview = await session.PreviewRevokeAllAsync(userId, ct);
            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = new Dictionary<string, object?>
            {
                ["success"] = true,
                ["dryRun"] = true,
                ["wouldRevoke"] = preview.Count,
                ["sampleSessionIds"] = preview.SampleSessionIds
            };
            exchange.Properties["identity-event-type"] = IdentityAuditEventIds.AllSessionsRevocationPreviewed;
            exchange.Properties["identity-event-data"] = new { UserId = userId, WouldRevoke = preview.Count };
            return;
        }

        var revoked = await session.RevokeAllAsync(userId, ct);
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new Dictionary<string, object?> { ["success"] = true, ["revoked"] = revoked };
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.AllSessionsRevoked;
        exchange.Properties["identity-event-data"] = new { UserId = userId };
    }

    /// <summary>
    /// Pulls the optional <c>dryRun</c> flag from the request body. Accepts <c>bool</c> or string
    /// equivalents (case-insensitive "true"/"false"). Missing key → <c>false</c>.
    /// </summary>
    private static bool ExtractDryRun(IExchange exchange)
    {
        if (exchange.In.Body is not Dictionary<string, object?> dict)
            return false;
        if (!dict.TryGetValue("dryRun", out var raw) || raw is null)
            return false;
        return raw switch
        {
            bool b => b,
            string s => bool.TryParse(s, out var parsed) && parsed,
            _ => false
        };
    }

    private static async Task Logout(SessionService session, IExchange exchange, CancellationToken ct)
    {
        var userId = IdentityProcessorHelpers.ExtractRequiredLong(exchange, "userId");
        var revoked = await session.LogoutAsync(userId, ct);
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new Dictionary<string, object?> { ["success"] = true, ["sessionsRevoked"] = revoked };
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.UserLoggedOut;
        exchange.Properties["identity-event-data"] = new { UserId = userId };
    }
}
