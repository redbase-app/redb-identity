using redb.Core;
using redb.Core.Models.Entities;
using redb.Core.Query;
using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Tokens;
using redb.Identity.Core.Models;
using redb.Route.Abstractions;
using redb.Route.RedbCore.Extensions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// Administrative token management processor.
/// Dispatches on: list, revoke, revoke-by-user, prune.
/// </summary>
internal sealed class TokenManagementProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;
    private readonly TokenCleanupProcessor? _cleanupProcessor;

    public TokenManagementProcessor(IRouteContext context, string? redbName = null, TokenCleanupProcessor? cleanupProcessor = null)
    {
        _context = context;
        _redbName = redbName;
        _cleanupProcessor = cleanupProcessor;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var redb = _context.GetRedbService(_redbName, exchange);
        var operation = exchange.In.GetHeader<string>("operation")
            ?? throw new InvalidOperationException("Missing 'operation' header");

        switch (operation)
        {
            case "list":
                await List(redb, exchange, ct);
                break;
            case "revoke":
                await Revoke(redb, exchange, ct);
                break;
            case "revoke-by-user":
                await RevokeByUser(redb, exchange, ct);
                break;
            case "prune":
                if (_cleanupProcessor is null)
                {
                    exchange.Out ??= new redb.Route.Core.Message();
                    exchange.Out.Body = new { error = "not_configured", error_description = "Token cleanup not configured" };
                }
                else
                {
                    await _cleanupProcessor.Process(exchange, ct);
                }
                break;
            default:
                exchange.Out ??= new redb.Route.Core.Message();
                exchange.Out.Body = new { error = "invalid_operation", error_description = $"Unknown operation: {operation}" };
                break;
        }
    }

    private async Task List(IRedbService _redb, IExchange exchange, CancellationToken ct)
    {
        var query = _redb.Query<TokenProps>();

        // Apply filters from body
        if (exchange.In.Body is Dictionary<string, object?> filters)
        {
            // Subject is now a GUID (the public sub claim). Accept either a Guid value
            // or a string parseable as Guid.
            if (filters.TryGetValue("subject", out var subVal) && subVal is not null)
            {
                Guid? subjectGuid = subVal switch
                {
                    Guid g => g,
                    string s when Guid.TryParse(s, out var parsed) => parsed,
                    _ => null
                };
                if (subjectGuid is not null && subjectGuid.Value != Guid.Empty)
                    query = query.WhereRedb(o => o.ValueGuid == subjectGuid.Value);
            }

            if (filters.TryGetValue("applicationObjectId", out var appVal) && appVal is long appId && appId > 0)
                query = query.Where(t => t.ApplicationObjectId == appId);

            if (filters.TryGetValue("status", out var statusVal) && statusVal is string status
                && !string.IsNullOrEmpty(status))
                query = query.Where(t => t.Status == status);

            if (filters.TryGetValue("type", out var typeVal) && typeVal is string type
                && !string.IsNullOrEmpty(type))
                query = query.Where(t => t.Type == type);
        }

        var offset = 0;
        var count = 20;
        if (exchange.In.Body is Dictionary<string, object?> paging)
        {
            if (paging.TryGetValue("offset", out var offVal) && offVal != null
                && int.TryParse(offVal.ToString(), out var off)) offset = off;
            if (paging.TryGetValue("count", out var cntVal) && cntVal != null
                && int.TryParse(cntVal.ToString(), out var cnt)) count = Math.Min(cnt, 100);
        }

        var total = await query.CountAsync();
        var items = await query
            .OrderByDescendingRedb(o => o.DateCreate)
            .Skip(offset)
            .Take(count)
            .ToListAsync();

        // Enrich each row with the human-readable bits the table renders:
        // subject GUID → user_id → login, application_id → client_id + display name.
        // Bulk-lookup so the page doesn't pay N+1.
        var subjectGuids = items
            .Select(t => t.value_guid)
            .Where(g => g.HasValue && g.Value != Guid.Empty)
            .Select(g => g!.Value)
            .Distinct()
            .ToArray();
        var subjectMap = new Dictionary<Guid, (long UserId, string Login)>();
        if (subjectGuids.Length > 0)
        {
            // WhereInRedb on a Guid? column produces a less obvious query shape
            // than per-guid equality; just fan out — the page size is bounded
            // (default 25, max 100) and the per-row lookup is cheap.
            foreach (var g in subjectGuids)
            {
                try
                {
                    var u = await _redb.Query<UserProps>()
                        .WhereRedb(o => o.ValueGuid == g)
                        .FirstOrDefaultAsync()
                        .ConfigureAwait(false);
                    if (u?.key is null) continue;
                    var core = await _redb.UserProvider.GetUserByIdAsync(u.key.Value).ConfigureAwait(false);
                    if (core is null) continue;
                    subjectMap[g] = (core.Id, core.Login);
                }
                catch { /* skip — best-effort label resolution */ }
            }
        }

        var appIds = items.Select(t => t.Props.ApplicationObjectId).Where(a => a > 0).Distinct().ToArray();
        var appsById = new Dictionary<long, RedbObject<ApplicationProps>>();
        if (appIds.Length > 0)
        {
            try
            {
                var apps = await _redb.Query<ApplicationProps>()
                    .WhereInRedb(o => o.Id, appIds)
                    .ToListAsync()
                    .ConfigureAwait(false);
                if (apps is not null)
                {
                    foreach (var app in apps)
                    {
                        if (app is null) continue;
                        appsById[app.id] = app.Hydrate();
                    }
                }
            }
            catch
            {
                // Best-effort label enrichment — if the application store is
                // unavailable / mocked-out the response just omits ClientId
                // and ApplicationName instead of failing the whole list call.
            }
        }

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new PagedResult<TokenInfoResponse>
        {
            Items = items.Select(t => MapToResponse(t, subjectMap, appsById)).ToList(),
            Total = total,
            Offset = offset,
            Count = count
        };
    }

    private async Task Revoke(IRedbService _redb, IExchange exchange, CancellationToken ct)
    {
        if (exchange.In.Body is not Dictionary<string, object?> dict
            || !dict.TryGetValue("tokenId", out var idVal) || idVal == null
            || !long.TryParse(idVal.ToString(), out var tokenId) || tokenId <= 0)
        {
            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = new { error = "validation_error", error_description = "tokenId is required" };
            return;
        }

        var token = await _redb.LoadAsync<TokenProps>(tokenId);
        if (token is null)
        {
            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = new { error = "not_found", error_description = $"Token {tokenId} not found" };
            return;
        }

        token.Props.Status = Statuses.Revoked;
        await _redb.SaveAsync(token);

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new { success = true };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.TokenRevoked;
        exchange.Properties["identity-event-data"] = new { TokenId = tokenId };
    }

    private async Task RevokeByUser(IRedbService _redb, IExchange exchange, CancellationToken ct)
    {
        if (exchange.In.Body is not Dictionary<string, object?> dict
            || !dict.TryGetValue("userId", out var idVal) || idVal == null
            || !long.TryParse(idVal.ToString(), out var userId) || userId <= 0)
        {
            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = new { error = "validation_error", error_description = "userId is required" };
            return;
        }

        // Subject column on TokenProps is now value_guid (the public sub). Resolve the
        // user's GUID from their UserProps record so the admin "revoke all tokens for
        // user X" call still works against the new index.
        var userObj = await _redb.Query<UserProps>()
            .WhereRedb(o => o.Key == userId)
            .FirstOrDefaultAsync();
        var subjectGuid = userObj?.value_guid ?? Guid.Empty;
        if (subjectGuid == Guid.Empty)
        {
            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = new { revokedCount = 0 };
            return;
        }

        var tokens = await _redb.Query<TokenProps>()
            .WhereRedb(o => o.ValueGuid == subjectGuid)
            .Where(t => t.Status == Statuses.Valid)
            .ToListAsync();

        foreach (var token in tokens)
        {
            token.Props.Status = Statuses.Revoked;
            await _redb.SaveAsync(token);
        }

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new { revokedCount = tokens.Count };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.TokensRevokedByUser;
        exchange.Properties["identity-event-data"] = new { UserId = userId, Count = tokens.Count };
    }

    private static TokenInfoResponse MapToResponse(RedbObject<TokenProps> token) =>
        MapToResponse(token, new Dictionary<Guid, (long, string)>(), new Dictionary<long, RedbObject<ApplicationProps>>());

    private static TokenInfoResponse MapToResponse(
        RedbObject<TokenProps> token,
        Dictionary<Guid, (long UserId, string Login)> subjectMap,
        Dictionary<long, RedbObject<ApplicationProps>> appsById)
    {
        var resp = new TokenInfoResponse
        {
            Id = token.Id,
            ApplicationObjectId = token.Props.ApplicationObjectId,
            Subject = token.value_guid?.ToString("D"),
            Status = token.Props.Status,
            Type = token.Props.Type,
            CreatedAt = token.DateCreate,
            ExpiresAt = token.date_complete
        };
        if (token.value_guid is Guid g && subjectMap.TryGetValue(g, out var subj))
        {
            resp.SubjectUserId = subj.UserId;
            resp.SubjectLogin = subj.Login;
        }
        if (token.Props.ApplicationObjectId > 0
            && appsById.TryGetValue(token.Props.ApplicationObjectId, out var app))
        {
            resp.ClientId = app.value_string;
            resp.ApplicationName = app.name;
        }
        return resp;
    }
}
