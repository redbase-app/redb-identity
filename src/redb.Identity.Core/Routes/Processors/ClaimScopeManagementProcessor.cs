using Microsoft.Extensions.DependencyInjection;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Core.Services;
using redb.Identity.Contracts.ClaimMappers;
using redb.Identity.Contracts.Common;
using redb.Identity.Core.Models;
using redb.Identity.Core.Module;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.RedbCore.Extensions;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// H5 (v1.0 DoD §5): CRUD management processor for reusable Client Scopes
/// (<see cref="ClaimScopeProps"/>) AND for Application↔Scope assignments
/// (<see cref="ClaimScopeAssignmentProps"/>).
/// <para>
/// Operations dispatched on the <c>operation</c> header:
/// <list type="bullet">
///   <item>Scope CRUD: <c>create | read | update | delete | list</c>.</item>
///   <item>Assignments: <c>assign | unassign | list-assignments</c>
///   (the latter requires header <c>applicationId</c>).</item>
/// </list>
/// </para>
/// </summary>
internal sealed class ClaimScopeManagementProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;

    public ClaimScopeManagementProcessor(IRouteContext context, string? redbName = null)
    {
        _context = context;
        _redbName = redbName;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var redb = _context.GetRedbService(_redbName, exchange);
        var operation = exchange.In.GetHeader<string>("operation")
            ?? throw new InvalidOperationException("Missing 'operation' header");

        switch (operation)
        {
            case "create":           await CreateScope(redb, exchange); break;
            case "read":             await ReadScope(redb, exchange); break;
            case "update":           await UpdateScope(redb, exchange); break;
            case "delete":           await DeleteScope(redb, exchange); break;
            case "list":             await ListScopes(redb, exchange); break;
            case "assign":           await Assign(redb, exchange); break;
            case "unassign":         await Unassign(redb, exchange); break;
            case "list-assignments": await ListAssignments(redb, exchange); break;
            default:
                exchange.Out ??= new redb.Route.Core.Message();
                exchange.Out.Body = new { error = "invalid_operation", error_description = $"Unknown operation: {operation}" };
                break;
        }
    }

    // ── Scope CRUD ──

    private static async Task CreateScope(IRedbService redb, IExchange exchange)
    {
        var request = exchange.In.Body as CreateClaimScopeRequest;
        if (request is null)
        { SetError(exchange, "validation_error", "Request body is required"); return; }

        var err = IdentityProcessorHelpers.ValidateIdentifier(request.Name, "Name");
        if (err != null) { SetError(exchange, "validation_error", err); return; }
        err = IdentityProcessorHelpers.ValidateDisplayName(request.DisplayName, "DisplayName");
        if (err != null) { SetError(exchange, "validation_error", err); return; }
        err = IdentityProcessorHelpers.ValidateDescription(request.Description, "Description");
        if (err != null) { SetError(exchange, "validation_error", err); return; }

        var existing = await redb.Query<ClaimScopeProps>()
            .WhereRedb(o => o.ValueString == request.Name)
            .FirstOrDefaultAsync().ConfigureAwait(false);
        if (existing != null)
        { SetError(exchange, "duplicate", $"ClaimScope '{request.Name}' already exists"); return; }

        var obj = new RedbObject<ClaimScopeProps>(new ClaimScopeProps
        {
            ScopeName = request.Name,
            Description = request.Description,
            Enabled = request.Enabled,
        });
        obj.Name = request.DisplayName ?? request.Name;
        obj.value_string = request.Name;

        try { await redb.SaveAsync(obj).ConfigureAwait(false); }
        catch (Exception ex) when (IdentityProcessorHelpers.IsUniqueViolation(ex))
        { SetError(exchange, "duplicate", $"ClaimScope '{request.Name}' already exists"); return; }

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = MapScope(obj);
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ClaimScopeCreated;
        exchange.Properties["identity-event-data"] = new { Id = obj.Id, Name = request.Name };
    }

    private static async Task ReadScope(IRedbService redb, IExchange exchange)
    {
        RedbObject<ClaimScopeProps>? scope = null;
        if (exchange.In.Body is Dictionary<string, object?> dict)
        {
            if (dict.TryGetValue("id", out var idVal) && idVal != null
                && long.TryParse(idVal.ToString(), out var id) && id > 0)
                scope = (await redb.LoadAsync<ClaimScopeProps>(id).ConfigureAwait(false))?.Hydrate();
            else if (dict.TryGetValue("name", out var nVal) && nVal is string name && !string.IsNullOrEmpty(name))
                scope = (await redb.Query<ClaimScopeProps>()
                    .WhereRedb(o => o.ValueString == name).FirstOrDefaultAsync().ConfigureAwait(false))?.Hydrate();
            else
            { SetError(exchange, "validation_error", "Either 'id' or 'name' required"); return; }
        }
        else
        { SetError(exchange, "validation_error", "Expected body with 'id' or 'name'"); return; }

        if (scope is null)
        { SetError(exchange, "not_found", "ClaimScope not found"); return; }

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = MapScope(scope);
    }

    private static async Task UpdateScope(IRedbService redb, IExchange exchange)
    {
        var request = exchange.In.Body as UpdateClaimScopeRequest;
        if (request is null || !long.TryParse(request.Id, out var id) || id <= 0)
        { SetError(exchange, "validation_error", "Id is required"); return; }

        var scope = (await redb.LoadAsync<ClaimScopeProps>(id).ConfigureAwait(false))?.Hydrate();
        if (scope is null) { SetError(exchange, "not_found", $"ClaimScope {id} not found"); return; }

        if (request.DisplayName != null)
        {
            var err = IdentityProcessorHelpers.ValidateDisplayName(request.DisplayName, "DisplayName");
            if (err != null) { SetError(exchange, "validation_error", err); return; }
            scope.Name = request.DisplayName;
        }
        if (request.Description != null)
        {
            var err = IdentityProcessorHelpers.ValidateDescription(request.Description, "Description");
            if (err != null) { SetError(exchange, "validation_error", err); return; }
            scope.Props.Description = request.Description;
        }
        if (request.Enabled.HasValue) scope.Props.Enabled = request.Enabled.Value;

        await redb.SaveAsync(scope).ConfigureAwait(false);

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = MapScope(scope);
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ClaimScopeUpdated;
        exchange.Properties["identity-event-data"] = new { Id = id, scope.Props.ScopeName };
    }

    private async Task DeleteScope(IRedbService redb, IExchange exchange)
    {
        if (exchange.In.Body is not Dictionary<string, object?> dict
            || !dict.TryGetValue("id", out var idVal) || idVal == null
            || !long.TryParse(idVal.ToString(), out var id) || id <= 0)
        { SetError(exchange, "validation_error", "Id is required"); return; }

        // Cascade: delete all assignments referencing this scope, plus all mapper rules under it.
        var assignments = await redb.Query<ClaimScopeAssignmentProps>()
            .WhereRedb(o => o.Key == id).ToListAsync().ConfigureAwait(false);
        // (assignments use `key=ApplicationId` for the index; assigned ScopeId is in props)
        assignments.AddRange(await redb.Query<ClaimScopeAssignmentProps>()
            .Where(p => p.ScopeId == id).ToListAsync().ConfigureAwait(false));

        var bg = _context.GetIdentityServiceOrDefault<IBackgroundDeletionService>(exchange);
        var assignmentIds = assignments.Select(a => a.Id).Distinct().ToList();
        foreach (var aid in assignmentIds)
            await IdentityDeletionHelper.DeleteAsync(redb, bg, aid).ConfigureAwait(false);

        var childMappers = await redb.Query<ClaimMapperProps>()
            .WhereRedb(o => o.ParentId == id).ToListAsync().ConfigureAwait(false);
        foreach (var cm in childMappers)
            await IdentityDeletionHelper.DeleteAsync(redb, bg, cm.Id).ConfigureAwait(false);

        await IdentityDeletionHelper.DeleteAsync(redb, bg, id).ConfigureAwait(false);

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new { success = true, cascadedAssignments = assignmentIds.Count, cascadedMappers = childMappers.Count };
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ClaimScopeDeleted;
        exchange.Properties["identity-event-data"] = new { Id = id };
    }

    private static async Task ListScopes(IRedbService redb, IExchange exchange)
    {
        var request = exchange.In.Body as ListRequest ?? new ListRequest();
        var query = redb.Query<ClaimScopeProps>().OrderByRedb(o => o.Id);
        var total = await query.CountAsync().ConfigureAwait(false);
        var count = Math.Min(request.Count, 100);
        var items = await query.Skip(request.Offset).Take(count).ToListAsync().ConfigureAwait(false);
        items.ForEach(i => i.Hydrate());

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new PagedResult<ClaimScopeResponse>
        {
            Items = items.Select(MapScope).ToList(),
            Total = total,
            Offset = request.Offset,
            Count = request.Count,
        };
    }

    // ── Assignments ──

    private static async Task Assign(IRedbService redb, IExchange exchange)
    {
        var request = exchange.In.Body as AssignClaimScopeRequest;
        if (request is null)
        { SetError(exchange, "validation_error", "Request body is required"); return; }
        if (!long.TryParse(request.ApplicationId, out var appId) || appId <= 0)
        { SetError(exchange, "validation_error", "applicationId must be a positive integer"); return; }
        if (!long.TryParse(request.ScopeId, out var scopeId) || scopeId <= 0)
        { SetError(exchange, "validation_error", "scopeId must be a positive integer"); return; }

        var app = await redb.LoadAsync<ApplicationProps>(appId).ConfigureAwait(false);
        if (app is null) { SetError(exchange, "not_found", $"Application {appId} not found"); return; }
        var scope = await redb.LoadAsync<ClaimScopeProps>(scopeId).ConfigureAwait(false);
        if (scope is null) { SetError(exchange, "not_found", $"ClaimScope {scopeId} not found"); return; }

        // Idempotent: if assignment already exists, return it
        var existing = await redb.Query<ClaimScopeAssignmentProps>()
            .WhereRedb(o => o.Key == appId)
            .Where(p => p.ScopeId == scopeId)
            .FirstOrDefaultAsync().ConfigureAwait(false);
        if (existing is not null)
        {
            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = MapAssignment(existing, scope.Hydrate());
            return;
        }

        var now = DateTimeOffset.UtcNow;
        var assignment = new RedbObject<ClaimScopeAssignmentProps>(new ClaimScopeAssignmentProps
        {
            ApplicationId = appId,
            ScopeId = scopeId,
            AssignedAt = now,
        });
        assignment.Name = $"{appId}::{scopeId}";
        assignment.key = appId;

        await redb.SaveAsync(assignment).ConfigureAwait(false);

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = MapAssignment(assignment, scope.Hydrate());

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ClaimScopeAssigned;
        exchange.Properties["identity-event-data"] = new { ApplicationId = appId, ScopeId = scopeId };
    }

    private async Task Unassign(IRedbService redb, IExchange exchange)
    {
        if (exchange.In.Body is not Dictionary<string, object?> dict)
        { SetError(exchange, "validation_error", "Body required"); return; }

        long appId = 0, scopeId = 0, assignmentId = 0;
        if (dict.TryGetValue("id", out var idVal) && idVal != null && long.TryParse(idVal.ToString(), out var aid) && aid > 0)
            assignmentId = aid;
        if (dict.TryGetValue("applicationId", out var appVal) && appVal != null && long.TryParse(appVal.ToString(), out var av) && av > 0)
            appId = av;
        if (dict.TryGetValue("scopeId", out var sv) && sv != null && long.TryParse(sv.ToString(), out var svv) && svv > 0)
            scopeId = svv;

        if (assignmentId == 0)
        {
            if (appId == 0 || scopeId == 0)
            { SetError(exchange, "validation_error", "Either id, or both applicationId+scopeId required"); return; }

            var existing = await redb.Query<ClaimScopeAssignmentProps>()
                .WhereRedb(o => o.Key == appId)
                .Where(p => p.ScopeId == scopeId)
                .FirstOrDefaultAsync().ConfigureAwait(false);
            if (existing is null) { SetError(exchange, "not_found", "Assignment not found"); return; }
            assignmentId = existing.Id;
            appId = existing.Props.ApplicationId;
            scopeId = existing.Props.ScopeId;
        }
        else
        {
            var existing = await redb.LoadAsync<ClaimScopeAssignmentProps>(assignmentId).ConfigureAwait(false);
            if (existing is null) { SetError(exchange, "not_found", "Assignment not found"); return; }
            appId = existing.Props.ApplicationId;
            scopeId = existing.Props.ScopeId;
        }

        var bg = _context.GetIdentityServiceOrDefault<IBackgroundDeletionService>(exchange);
        await IdentityDeletionHelper.DeleteAsync(redb, bg, assignmentId).ConfigureAwait(false);

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new { success = true };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ClaimScopeUnassigned;
        exchange.Properties["identity-event-data"] = new { ApplicationId = appId, ScopeId = scopeId };
    }

    private static async Task ListAssignments(IRedbService redb, IExchange exchange)
    {
        var appHeader = exchange.In.GetHeader<string>("applicationId");
        if (string.IsNullOrEmpty(appHeader) && exchange.In.Body is Dictionary<string, object?> bodyDict
            && bodyDict.TryGetValue("applicationId", out var appVal) && appVal != null)
            appHeader = appVal.ToString();
        if (string.IsNullOrEmpty(appHeader) || !long.TryParse(appHeader, out var appId) || appId <= 0)
        { SetError(exchange, "validation_error", "applicationId (positive integer) is required"); return; }

        var assignments = await redb.Query<ClaimScopeAssignmentProps>()
            .WhereRedb(o => o.Key == appId).ToListAsync().ConfigureAwait(false);

        var scopeIds = assignments.Select(a => a.Props.ScopeId).Distinct().ToList();
        var scopes = scopeIds.Count == 0
            ? new List<RedbObject<ClaimScopeProps>>()
            : await redb.Query<ClaimScopeProps>()
                .WhereInRedb(o => o.Id, scopeIds).ToListAsync().ConfigureAwait(false);
        scopes.ForEach(s => s.Hydrate());
        var scopeMap = scopes.ToDictionary(s => s.Id);

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new PagedResult<ClaimScopeAssignmentResponse>
        {
            Items = assignments
                .Select(a => MapAssignment(a, scopeMap.GetValueOrDefault(a.Props.ScopeId)))
                .ToList(),
            Total = assignments.Count,
            Offset = 0,
            Count = assignments.Count,
        };
    }

    // ── helpers ──

    private static void SetError(IExchange exchange, string error, string description)
        => IdentityProcessorHelpers.SetError(exchange, error, description);

    private static ClaimScopeResponse MapScope(RedbObject<ClaimScopeProps> obj) => new()
    {
        Id = obj.Id.ToString(),
        Name = obj.Props.ScopeName,
        DisplayName = obj.Name,
        Description = obj.Props.Description,
        Enabled = obj.Props.Enabled,
    };

    private static ClaimScopeAssignmentResponse MapAssignment(
        RedbObject<ClaimScopeAssignmentProps> obj, RedbObject<ClaimScopeProps>? scope) => new()
    {
        Id = obj.Id.ToString(),
        ApplicationId = obj.Props.ApplicationId.ToString(),
        ScopeId = obj.Props.ScopeId.ToString(),
        ScopeName = scope?.Props.ScopeName,
        AssignedAt = obj.Props.AssignedAt,
        AssignedBy = obj.Props.AssignedBy?.ToString(),
    };
}
