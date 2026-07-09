using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Roles;
using redb.Identity.Contracts.Routes;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.RedbCore.Extensions;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// B.3 — admin CRUD + assignment surface for the Roles registry.
///
/// Operations:
///   search / get / create / update / delete                         — role CRUD
///   list-assignees / assign-user / unassign-user
///                / assign-group / unassign-group                    — assignments
///   user-roles (effective set)                                      — read-only
/// </summary>
internal sealed class RoleManagementProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;
    private readonly ILogger<RoleManagementProcessor> _logger;

    public RoleManagementProcessor(IRouteContext context, string? redbName, ILogger<RoleManagementProcessor> logger)
    {
        _context = context;
        _redbName = redbName;
        _logger = logger;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var operation = exchange.In.GetHeader<string>("operation") ?? "";
        var redb = _context.GetRedbService(_redbName, exchange);
        var svc = new RoleService(redb);

        switch (operation)
        {
            case "search":          await Search(redb, svc, exchange, ct); break;
            case "get":             await Get(redb, svc, exchange, ct); break;
            case "create":          await Create(redb, svc, exchange, ct); break;
            case "update":          await Update(svc, exchange, ct); break;
            case "delete":          await Delete(svc, exchange, ct); break;
            case "list-assignees":  await ListAssignees(redb, svc, exchange, ct); break;
            case "assign-user":     await AssignUser(svc, exchange, ct); break;
            case "unassign-user":   await UnassignUser(svc, exchange, ct); break;
            case "assign-group":    await AssignGroup(svc, exchange, ct); break;
            case "unassign-group":  await UnassignGroup(svc, exchange, ct); break;
            case "list-scopes":     await ListScopes(redb, svc, exchange, ct); break;
            case "attach-scope":    await AttachScope(svc, exchange, ct); break;
            case "detach-scope":    await DetachScope(svc, exchange, ct); break;
            default:
                SetError(exchange, "invalid_operation", $"Unknown operation: {operation}");
                break;
        }
    }

    // ── Role CRUD ──────────────────────────────────────────────

    private async Task Search(IRedbService redb, RoleService svc, IExchange exchange, CancellationToken ct)
    {
        var dict = exchange.In.Body as Dictionary<string, object?> ?? new();
        string? query = dict.TryGetValue("query", out var q) ? q?.ToString() : null;
        string? audience = dict.TryGetValue("audience", out var a) ? a?.ToString() : null;
        long? applicationId = null;
        if (dict.TryGetValue("applicationId", out var app) && long.TryParse(app?.ToString(), out var pa))
            applicationId = pa;
        var offset = 0;
        var count = 25;
        if (dict.TryGetValue("offset", out var oVal) && int.TryParse(oVal?.ToString(), out var po)) offset = Math.Max(0, po);
        if (dict.TryGetValue("count", out var cVal) && int.TryParse(cVal?.ToString(), out var pc)) count = Math.Clamp(pc, 1, 200);

        var (items, total) = await svc.SearchRolesAsync(
            string.IsNullOrWhiteSpace(query) ? null : query,
            string.IsNullOrWhiteSpace(audience) ? null : audience,
            applicationId,
            offset, count, ct).ConfigureAwait(false);

        var counts = await svc.CountAssignmentsByRoleAsync(items.Select(r => r.Id), ct).ConfigureAwait(false);

        // Bulk-resolve application display names for audience='application' rows.
        var appIds = items
            .Where(r => r.Props.ApplicationId.HasValue)
            .Select(r => r.Props.ApplicationId!.Value)
            .Distinct()
            .ToList();
        var appNames = await ResolveApplicationNamesAsync(redb, appIds).ConfigureAwait(false);

        var responses = items.Select(r => MapToResponse(r, appNames, counts.GetValueOrDefault(r.Id, 0))).ToList();

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new PagedResult<RoleResponse>
        {
            Items = responses,
            Total = total,
            Offset = offset,
            Count = count
        };
    }

    private async Task Get(IRedbService redb, RoleService svc, IExchange exchange, CancellationToken ct)
    {
        var id = ExtractLongFromBody(exchange, "id");
        if (id is null) { SetError(exchange, "validation_error", "id is required"); return; }
        var role = await svc.GetRoleAsync(id.Value, ct).ConfigureAwait(false);
        if (role is null) { SetError(exchange, "not_found", $"Role {id} not found"); return; }

        var appNames = role.Props.ApplicationId.HasValue
            ? await ResolveApplicationNamesAsync(redb, new[] { role.Props.ApplicationId.Value }).ConfigureAwait(false)
            : new Dictionary<long, string>();
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = MapToResponse(role, appNames, null);
    }

    private async Task Create(IRedbService redb, RoleService svc, IExchange exchange, CancellationToken ct)
    {
        if (exchange.In.Body is not CreateRoleRequest request)
        {
            SetError(exchange, "validation_error", "Body must be a CreateRoleRequest");
            return;
        }

        var name = request.Name.Trim();
        if (string.IsNullOrEmpty(name)) { SetError(exchange, "validation_error", "name is required"); return; }
        if (request.Audience is not ("organization" or "application"))
        {
            SetError(exchange, "validation_error", "audience must be 'organization' or 'application'");
            return;
        }
        if (request.Audience == "application" && (request.ApplicationId is null or 0))
        {
            SetError(exchange, "validation_error", "audience='application' requires applicationId");
            return;
        }
        if (request.Audience == "organization" && request.ApplicationId is not null)
        {
            SetError(exchange, "validation_error", "audience='organization' requires applicationId to be null");
            return;
        }

        try
        {
            var created = await svc.CreateRoleAsync(
                name, request.Audience, request.ApplicationId,
                request.DisplayName, request.Description,
                isSystem: false, ct).ConfigureAwait(false);

            var appNames = request.ApplicationId.HasValue
                ? await ResolveApplicationNamesAsync(redb, new[] { request.ApplicationId.Value }).ConfigureAwait(false)
                : new Dictionary<long, string>();
            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = MapToResponse(created, appNames, 0);

            exchange.Properties["identity-event-type"] = IdentityAuditEventIds.RoleCreated;
            exchange.Properties["identity-event-data"] = new { RoleId = created.Id, Name = name };
        }
        catch (InvalidOperationException ex)
        {
            SetError(exchange, "conflict", ex.Message);
        }
    }

    private async Task Update(RoleService svc, IExchange exchange, CancellationToken ct)
    {
        var id = ExtractLongFromBody(exchange, "id");
        if (id is null) { SetError(exchange, "validation_error", "id is required"); return; }

        var dict = exchange.In.Body as Dictionary<string, object?>;
        string? displayName = dict?.TryGetValue("displayName", out var dn) == true ? dn?.ToString() : null;
        string? description = dict?.TryGetValue("description", out var dd) == true ? dd?.ToString() : null;

        await svc.UpdateRoleAsync(id.Value, displayName, description, ct).ConfigureAwait(false);
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new { success = true };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.RoleUpdated;
        exchange.Properties["identity-event-data"] = new { RoleId = id.Value };
    }

    private async Task Delete(RoleService svc, IExchange exchange, CancellationToken ct)
    {
        var id = ExtractLongFromBody(exchange, "id");
        if (id is null) { SetError(exchange, "validation_error", "id is required"); return; }
        try
        {
            await svc.DeleteRoleAsync(id.Value, ct).ConfigureAwait(false);
            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = new { success = true };

            exchange.Properties["identity-event-type"] = IdentityAuditEventIds.RoleDeleted;
            exchange.Properties["identity-event-data"] = new { RoleId = id.Value };
        }
        catch (InvalidOperationException ex)
        {
            SetError(exchange, "conflict", ex.Message);
        }
    }

    // ── Assignments ────────────────────────────────────────────

    private async Task ListAssignees(IRedbService redb, RoleService svc, IExchange exchange, CancellationToken ct)
    {
        var roleId = ExtractLongFromBody(exchange, "roleId") ?? ExtractLongFromBody(exchange, "id");
        if (roleId is null) { SetError(exchange, "validation_error", "roleId is required"); return; }

        var (userIds, groupIds) = await svc.ListAssigneesAsync(roleId.Value, ct).ConfigureAwait(false);

        // Best-effort lookup user logins + group names for labels.
        // Earlier impl used GetUsersAsync(new UserSearchCriteria { Limit = N })
        // which returned the first N users (unsorted by id, no filter) and
        // then .Where(userIds.Contains)-filtered them — i.e. on any install
        // with more than N users the assignee's actual record would not be
        // in the response and the UI showed only the raw id. Per-id lookup
        // through the dedicated provider entry-point is correct at any
        // user count; bounded by the assignee list (usually <100).
        var userLabels = new Dictionary<long, string>();
        if (userIds.Count > 0)
        {
            try
            {
                var lookups = userIds.Select(async id =>
                {
                    try { return (id, user: await redb.UserProvider.GetUserByIdAsync(id).ConfigureAwait(false)); }
                    catch { return (id, user: (redb.Core.Models.Contracts.IRedbUser?)null); }
                });
                foreach (var (id, user) in await Task.WhenAll(lookups))
                {
                    if (user is not null) userLabels[id] = user.Login;
                }
            }
            catch { /* swallow */ }
        }
        var groupLabels = new Dictionary<long, string>();
        if (groupIds.Count > 0)
        {
            try
            {
                var groups = await redb.Query<GroupProps>()
                    .WhereInRedb(o => o.Id, groupIds.Cast<long>())
                    .ToListAsync()
                    .ConfigureAwait(false);
                foreach (var g in groups) groupLabels[g.Id] = g.Name ?? $"group:{g.Id}";
            }
            catch { /* swallow */ }
        }

        var role = await svc.GetRoleAsync(roleId.Value, ct).ConfigureAwait(false);
        var roleName = role?.Props.Name ?? "";
        var audience = role?.Props.Audience ?? "organization";
        var appId = role?.Props.ApplicationId;

        var rows = new List<RoleAssignmentResponse>();
        foreach (var uid in userIds)
        {
            rows.Add(new RoleAssignmentResponse
            {
                RoleId = roleId.Value, RoleName = roleName, Audience = audience, ApplicationId = appId,
                SubjectKind = "user", SubjectId = uid,
                SubjectLabel = userLabels.GetValueOrDefault(uid),
                AssignedAt = DateTimeOffset.UtcNow,
            });
        }
        foreach (var gid in groupIds)
        {
            rows.Add(new RoleAssignmentResponse
            {
                RoleId = roleId.Value, RoleName = roleName, Audience = audience, ApplicationId = appId,
                SubjectKind = "group", SubjectId = gid,
                SubjectLabel = groupLabels.GetValueOrDefault(gid),
                AssignedAt = DateTimeOffset.UtcNow,
            });
        }

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = rows;
    }

    private async Task AssignUser(RoleService svc, IExchange exchange, CancellationToken ct)
    {
        var roleId = ExtractLongFromBody(exchange, "roleId");
        var userId = ExtractLongFromBody(exchange, "userId");
        if (roleId is null || userId is null)
        {
            SetError(exchange, "validation_error", "roleId + userId required");
            return;
        }
        await svc.AssignUserAsync(roleId.Value, userId.Value, null, ct).ConfigureAwait(false);
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new { success = true };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.RoleAssignedUser;
        exchange.Properties["identity-event-data"] = new { RoleId = roleId.Value, UserId = userId.Value };
    }

    private async Task UnassignUser(RoleService svc, IExchange exchange, CancellationToken ct)
    {
        var roleId = ExtractLongFromBody(exchange, "roleId");
        var userId = ExtractLongFromBody(exchange, "userId");
        if (roleId is null || userId is null) { SetError(exchange, "validation_error", "roleId + userId required"); return; }
        await svc.UnassignUserAsync(roleId.Value, userId.Value, ct).ConfigureAwait(false);
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new { success = true };
    }

    private async Task AssignGroup(RoleService svc, IExchange exchange, CancellationToken ct)
    {
        var roleId = ExtractLongFromBody(exchange, "roleId");
        var groupId = ExtractLongFromBody(exchange, "groupId");
        if (roleId is null || groupId is null) { SetError(exchange, "validation_error", "roleId + groupId required"); return; }
        await svc.AssignGroupAsync(roleId.Value, groupId.Value, null, ct).ConfigureAwait(false);
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new { success = true };
    }

    private async Task UnassignGroup(RoleService svc, IExchange exchange, CancellationToken ct)
    {
        var roleId = ExtractLongFromBody(exchange, "roleId");
        var groupId = ExtractLongFromBody(exchange, "groupId");
        if (roleId is null || groupId is null) { SetError(exchange, "validation_error", "roleId + groupId required"); return; }
        await svc.UnassignGroupAsync(roleId.Value, groupId.Value, ct).ConfigureAwait(false);
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new { success = true };
    }

    // ── Scope attachments ──────────────────────────────────────

    private async Task ListScopes(IRedbService redb, RoleService svc, IExchange exchange, CancellationToken ct)
    {
        var roleId = ExtractLongFromBody(exchange, "roleId") ?? ExtractLongFromBody(exchange, "id");
        if (roleId is null) { SetError(exchange, "validation_error", "roleId required"); return; }

        var scopeIds = await svc.ListScopeIdsForRoleAsync(roleId.Value, ct).ConfigureAwait(false);
        if (scopeIds.Count == 0)
        {
            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = new List<redb.Identity.Contracts.Roles.RoleScopeResponse>();
            return;
        }

        var scopes = await redb.Query<ScopeProps>()
            .WhereInRedb(o => o.Id, scopeIds.Cast<long>())
            .ToListAsync()
            .ConfigureAwait(false);

        // ScopeProps.ScopeName has [RedbIgnore] — the canonical scope name is
        // stored in _objects.value_string (indexed) rather than in PROPS.
        var rows = scopes.Select(s => new redb.Identity.Contracts.Roles.RoleScopeResponse
        {
            RoleId = roleId.Value,
            ScopeId = s.Id,
            ScopeName = s.value_string ?? s.name,
            Description = s.Props.Description,
            AttachedAt = s.date_create
        }).ToList();

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = rows;
    }

    private async Task AttachScope(RoleService svc, IExchange exchange, CancellationToken ct)
    {
        var roleId = ExtractLongFromBody(exchange, "roleId");
        var scopeId = ExtractLongFromBody(exchange, "scopeId");
        if (roleId is null || scopeId is null) { SetError(exchange, "validation_error", "roleId + scopeId required"); return; }

        await svc.AttachScopeAsync(roleId.Value, scopeId.Value, null, ct).ConfigureAwait(false);
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new { success = true };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.RoleScopeAttached;
        exchange.Properties["identity-event-data"] = new { RoleId = roleId.Value, ScopeId = scopeId.Value };
    }

    private async Task DetachScope(RoleService svc, IExchange exchange, CancellationToken ct)
    {
        var roleId = ExtractLongFromBody(exchange, "roleId");
        var scopeId = ExtractLongFromBody(exchange, "scopeId");
        if (roleId is null || scopeId is null) { SetError(exchange, "validation_error", "roleId + scopeId required"); return; }
        await svc.DetachScopeAsync(roleId.Value, scopeId.Value, ct).ConfigureAwait(false);
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new { success = true };
    }

    // ── Helpers ─────────────────────────────────────────────────

    private static long? ExtractLongFromBody(IExchange exchange, string field)
    {
        if (exchange.In.Body is not Dictionary<string, object?> dict) return null;
        if (!dict.TryGetValue(field, out var v) || v is null) return null;
        return long.TryParse(v.ToString(), out var parsed) ? parsed : null;
    }

    private static async Task<Dictionary<long, string>> ResolveApplicationNamesAsync(IRedbService redb, IEnumerable<long> ids)
    {
        var idList = ids.Distinct().ToList();
        if (idList.Count == 0) return new();
        try
        {
            var apps = await redb.Query<ApplicationProps>()
                .WhereInRedb(o => o.Id, idList.Cast<long>())
                .ToListAsync()
                .ConfigureAwait(false);
            return apps.ToDictionary(a => a.Id, a => a.Props.ClientId ?? $"app:{a.Id}");
        }
        catch { return new(); }
    }

    private static RoleResponse MapToResponse(redb.Core.Models.Entities.RedbObject<RoleProps> r,
        IReadOnlyDictionary<long, string> appNames, int? assignmentCount) => new()
    {
        Id = r.Id,
        Name = r.Props.Name,
        DisplayName = r.Props.DisplayName,
        Description = r.Props.Description,
        Audience = r.Props.Audience,
        ApplicationId = r.Props.ApplicationId,
        ApplicationName = r.Props.ApplicationId is { } aid ? appNames.GetValueOrDefault(aid) : null,
        IsSystem = r.Props.IsSystem,
        CreatedAt = r.date_create,
        ModifiedAt = r.date_modify,
        AssignmentCount = assignmentCount,
    };

    private static void SetError(IExchange exchange, string code, string description)
    {
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new { error = code, error_description = description };
    }
}
