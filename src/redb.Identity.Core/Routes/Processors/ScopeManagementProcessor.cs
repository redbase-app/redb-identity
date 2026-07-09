using Microsoft.Extensions.DependencyInjection;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Core.Services;
using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Scopes;
using redb.Identity.Core.Models;
using redb.Identity.Core.Module;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.RedbCore.Extensions;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// CRUD management processor for OAuth scopes.
/// Dispatches on the "operation" header: create, read, update, delete, list.
/// </summary>
internal sealed class ScopeManagementProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;

    public ScopeManagementProcessor(IRouteContext context, string? redbName = null)
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
            case "create":
                await Create(redb, exchange, ct);
                break;
            case "read":
                await Read(redb, exchange, ct);
                break;
            case "update":
                await Update(redb, exchange, ct);
                break;
            case "delete":
                await Delete(redb, exchange, ct);
                break;
            case "list":
                await List(redb, exchange, ct);
                break;
            default:
                exchange.Out ??= new redb.Route.Core.Message();
                exchange.Out.Body = new { error = "invalid_operation", error_description = $"Unknown operation: {operation}" };
                break;
        }
    }

    private async Task Create(IRedbService _redb, IExchange exchange, CancellationToken ct)
    {
        var request = exchange.In.Body as CreateScopeRequest;

        // Validate scope name
        var err = IdentityProcessorHelpers.ValidateIdentifier(request?.Name, "Name");
        if (err != null) { SetError(exchange, "validation_error", err); return; }

        err = IdentityProcessorHelpers.ValidateDisplayName(request!.DisplayName, "DisplayName");
        if (err != null) { SetError(exchange, "validation_error", err); return; }

        err = IdentityProcessorHelpers.ValidateDescription(request.Description, "Description");
        if (err != null) { SetError(exchange, "validation_error", err); return; }

        // Check uniqueness (indexed root field)
        var existing = await _redb.Query<ScopeProps>()
            .WhereRedb(o => o.ValueString == request.Name)
            .FirstOrDefaultAsync();
        if (existing != null)
        {
            SetError(exchange, "duplicate", $"Scope '{request.Name}' already exists");
            return;
        }

        var obj = new RedbObject<ScopeProps>(new ScopeProps
        {
            ScopeName = request.Name,
            Description = request.Description,
            Resources = request.Resources
        });
        obj.Name = request.DisplayName ?? request.Name;
        obj.value_string = request.Name;

        try
        {
            await _redb.SaveAsync(obj);
        }
        catch (Exception ex) when (IdentityProcessorHelpers.IsUniqueViolation(ex))
        {
            // Concurrent writer won the race — partial unique index on _objects
            // (_value_string) WHERE _id_scheme = ScopeProps rejected this insert.
            // Surface the same error as the app-level check above for clients.
            SetError(exchange, "duplicate", $"Scope '{request.Name}' already exists");
            return;
        }

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = MapToResponse(obj);

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ScopeCreated;
        exchange.Properties["identity-event-data"] = new { Name = request.Name };
    }

    private async Task Read(IRedbService _redb, IExchange exchange, CancellationToken ct)
    {
        RedbObject<ScopeProps>? scope = null;

        if (exchange.In.Body is Dictionary<string, object?> dict)
        {
            if (dict.TryGetValue("id", out var idVal) && idVal != null
                && long.TryParse(idVal.ToString(), out var id) && id > 0)
                scope = (await _redb.LoadAsync<ScopeProps>(id))?.Hydrate();
            else if (dict.TryGetValue("name", out var nVal) && nVal is string name
                     && !string.IsNullOrEmpty(name))
                scope = (await _redb.Query<ScopeProps>()
                    .WhereRedb(o => o.ValueString == name)
                    .FirstOrDefaultAsync())?.Hydrate();
            else
                throw new InvalidOperationException("Either 'id' or 'name' required");
        }
        else
        {
            throw new InvalidOperationException("Expected body with 'id' or 'name'");
        }

        if (scope is null)
        {
            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = new { error = "not_found", error_description = "Scope not found" };
            return;
        }

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = MapToResponse(scope);
    }

    private async Task Update(IRedbService _redb, IExchange exchange, CancellationToken ct)
    {
        var request = exchange.In.Body as UpdateScopeRequest;
        if (request is null || !long.TryParse(request.Id, out var objectId) || objectId <= 0)
        {
            SetError(exchange, "validation_error", "Id is required");
            return;
        }

        var scope = (await _redb.LoadAsync<ScopeProps>(objectId))?.Hydrate();
        if (scope is null)
        {
            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = new { error = "not_found", error_description = $"Scope {request.Id} not found" };
            return;
        }

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
        if (request.Resources != null) scope.Props.Resources = request.Resources;

        await _redb.SaveAsync(scope);

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = MapToResponse(scope);

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ScopeUpdated;
        exchange.Properties["identity-event-data"] = new { scope.Props.ScopeName };
    }

    private async Task Delete(IRedbService _redb, IExchange exchange, CancellationToken ct)
    {
        if (exchange.In.Body is not Dictionary<string, object?> dict
            || !dict.TryGetValue("id", out var idVal) || idVal == null
            || !long.TryParse(idVal.ToString(), out var id) || id <= 0)
        {
            SetError(exchange, "validation_error", "Id is required");
            return;
        }

        var bg = _context.GetIdentityServiceOrDefault<IBackgroundDeletionService>(exchange);
        await IdentityDeletionHelper.DeleteAsync(_redb, bg, id);

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new { success = true };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ScopeDeleted;
        exchange.Properties["identity-event-data"] = new { Id = id };
    }

    private async Task List(IRedbService _redb, IExchange exchange, CancellationToken ct)
    {
        var request = exchange.In.Body as ListRequest ?? new ListRequest();

        var query = _redb.Query<ScopeProps>()
            .OrderByRedb(o => o.Id);

        var total = await query.CountAsync();
        var count = Math.Min(request.Count, 100);
        var items = await query
            .Skip(request.Offset)
            .Take(count)
            .ToListAsync();
        items.ForEach(i => i.Hydrate());

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new PagedResult<ScopeResponse>
        {
            Items = items.Select(MapToResponse).ToList(),
            Total = total,
            Offset = request.Offset,
            Count = request.Count
        };
    }

    private static void SetError(IExchange exchange, string error, string description)
        => IdentityProcessorHelpers.SetError(exchange, error, description);

    private static ScopeResponse MapToResponse(RedbObject<ScopeProps> scope) => new()
    {
        Id = scope.Id.ToString(),
        Name = scope.Props.ScopeName,
        DisplayName = scope.Name,
        Description = scope.Props.Description,
        Resources = scope.Props.Resources
    };
}
