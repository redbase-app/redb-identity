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
/// H5 (v1.0 DoD §5): CRUD management processor for declarative claim mapping rules
/// (<see cref="ClaimMapperProps"/>). Operations dispatched on the <c>operation</c> header:
/// <c>create | read | update | delete | list</c>. <c>list</c> accepts an optional
/// <c>owner</c> filter (<c>"global"</c>, <c>"application:{id}"</c>, <c>"scope:{id}"</c>,
/// or omitted for all).
/// </summary>
internal sealed class ClaimMapperManagementProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;

    public ClaimMapperManagementProcessor(IRouteContext context, string? redbName = null)
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
            case "create": await Create(redb, exchange, ct); break;
            case "read":   await Read(redb, exchange, ct); break;
            case "update": await Update(redb, exchange, ct); break;
            case "delete": await Delete(redb, exchange, ct); break;
            case "list":   await List(redb, exchange, ct); break;
            default:
                exchange.Out ??= new redb.Route.Core.Message();
                exchange.Out.Body = new { error = "invalid_operation", error_description = $"Unknown operation: {operation}" };
                break;
        }
    }

    private static async Task Create(IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        var request = exchange.In.Body as CreateClaimMapperRequest;
        if (request is null)
        { SetError(exchange, "validation_error", "Request body is required"); return; }

        var err = IdentityProcessorHelpers.ValidateDisplayName(request.Name, "Name");
        if (err != null) { SetError(exchange, "validation_error", err); return; }
        if (string.IsNullOrWhiteSpace(request.ClaimType))
        { SetError(exchange, "validation_error", "ClaimType is required"); return; }
        var sourceErr = ValidateSource(request.SourceKind, request.SourcePath, request.ConstantValue);
        if (sourceErr != null) { SetError(exchange, "validation_error", sourceErr); return; }

        long? parentId;
        try { parentId = ParseOwner(request.Owner); }
        catch (FormatException ex) { SetError(exchange, "validation_error", ex.Message); return; }

        // Verify parent exists when not global
        if (parentId is long pid)
        {
            var parentExists = await redb.LoadAsync<ApplicationProps>(pid).ConfigureAwait(false) is not null
                || await redb.LoadAsync<ClaimScopeProps>(pid).ConfigureAwait(false) is not null;
            if (!parentExists)
            { SetError(exchange, "not_found", $"Owner object {pid} not found (must be Application or ClaimScope)"); return; }
        }

        var obj = new RedbObject<ClaimMapperProps>(new ClaimMapperProps
        {
            ClaimType = request.ClaimType.Trim(),
            SourceKind = request.SourceKind.Trim(),
            SourcePath = request.SourcePath,
            ConstantValue = request.ConstantValue,
            RequiredScopes = request.RequiredScopes,
            Destinations = request.Destinations,
            Required = request.Required,
            Order = request.Order,
            Enabled = request.Enabled,
            Description = request.Description,
        });
        obj.Name = request.Name;
        obj.ParentId = parentId;

        await redb.SaveAsync(obj).ConfigureAwait(false);

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = MapToResponse(obj);

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ClaimMapperCreated;
        exchange.Properties["identity-event-data"] = new { Id = obj.Id, request.ClaimType, Owner = OwnerString(parentId) };
    }

    private static async Task Read(IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        if (exchange.In.Body is not Dictionary<string, object?> dict
            || !dict.TryGetValue("id", out var idVal) || idVal == null
            || !long.TryParse(idVal.ToString(), out var id) || id <= 0)
        { SetError(exchange, "validation_error", "Id is required"); return; }

        var obj = await redb.LoadAsync<ClaimMapperProps>(id).ConfigureAwait(false);
        if (obj is null)
        { SetError(exchange, "not_found", $"ClaimMapper {id} not found"); return; }

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = MapToResponse(obj);
    }

    private static async Task Update(IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        var request = exchange.In.Body as UpdateClaimMapperRequest;
        if (request is null || !long.TryParse(request.Id, out var id) || id <= 0)
        { SetError(exchange, "validation_error", "Id is required"); return; }

        var obj = await redb.LoadAsync<ClaimMapperProps>(id).ConfigureAwait(false);
        if (obj is null)
        { SetError(exchange, "not_found", $"ClaimMapper {id} not found"); return; }

        if (request.Name != null) obj.Name = request.Name;
        if (request.ClaimType != null)
        {
            if (string.IsNullOrWhiteSpace(request.ClaimType))
            { SetError(exchange, "validation_error", "ClaimType cannot be empty"); return; }
            obj.Props.ClaimType = request.ClaimType.Trim();
        }
        var nextSourceKind = request.SourceKind ?? obj.Props.SourceKind;
        var nextSourcePath = request.SourcePath ?? obj.Props.SourcePath;
        var nextConstantValue = request.ConstantValue ?? obj.Props.ConstantValue;
        if (request.SourceKind != null || request.SourcePath != null || request.ConstantValue != null)
        {
            var srcErr = ValidateSource(nextSourceKind, nextSourcePath, nextConstantValue);
            if (srcErr != null) { SetError(exchange, "validation_error", srcErr); return; }
            obj.Props.SourceKind = nextSourceKind;
            obj.Props.SourcePath = nextSourcePath;
            obj.Props.ConstantValue = nextConstantValue;
        }
        if (request.RequiredScopes != null) obj.Props.RequiredScopes = request.RequiredScopes;
        if (request.Destinations != null) obj.Props.Destinations = request.Destinations;
        if (request.Required.HasValue) obj.Props.Required = request.Required.Value;
        if (request.Order.HasValue) obj.Props.Order = request.Order.Value;
        if (request.Enabled.HasValue) obj.Props.Enabled = request.Enabled.Value;
        if (request.Description != null) obj.Props.Description = request.Description;

        await redb.SaveAsync(obj).ConfigureAwait(false);

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = MapToResponse(obj);

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ClaimMapperUpdated;
        exchange.Properties["identity-event-data"] = new { Id = id, obj.Props.ClaimType };
    }

    private async Task Delete(IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        if (exchange.In.Body is not Dictionary<string, object?> dict
            || !dict.TryGetValue("id", out var idVal) || idVal == null
            || !long.TryParse(idVal.ToString(), out var id) || id <= 0)
        { SetError(exchange, "validation_error", "Id is required"); return; }

        var bg = _context.GetIdentityServiceOrDefault<IBackgroundDeletionService>(exchange);
        await IdentityDeletionHelper.DeleteAsync(redb, bg, id).ConfigureAwait(false);

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new { success = true };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ClaimMapperDeleted;
        exchange.Properties["identity-event-data"] = new { Id = id };
    }

    private static async Task List(IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        var request = exchange.In.Body as ListRequest ?? new ListRequest();
        // owner filter via header OR body extra-field
        var owner = exchange.In.GetHeader<string>("owner");
        if (string.IsNullOrEmpty(owner) && exchange.In.Body is Dictionary<string, object?> bodyDict
            && bodyDict.TryGetValue("owner", out var ownerVal) && ownerVal is string s)
            owner = s;

        var query = redb.Query<ClaimMapperProps>();

        if (!string.IsNullOrEmpty(owner))
        {
            long? parentFilter;
            try { parentFilter = ParseOwner(owner); }
            catch (FormatException ex) { SetError(exchange, "validation_error", ex.Message); return; }

            if (parentFilter is null)
                query = query.WhereRedb(o => o.ParentId == null);
            else
            {
                var pid = parentFilter.Value;
                query = query.WhereRedb(o => o.ParentId == pid);
            }
        }

        query = query.OrderByRedb(o => o.Id);

        var total = await query.CountAsync().ConfigureAwait(false);
        var count = Math.Min(request.Count, 100);
        var items = await query.Skip(request.Offset).Take(count).ToListAsync().ConfigureAwait(false);

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new PagedResult<ClaimMapperResponse>
        {
            Items = items.Select(MapToResponse).ToList(),
            Total = total,
            Offset = request.Offset,
            Count = request.Count,
        };
    }

    private static void SetError(IExchange exchange, string error, string description)
        => IdentityProcessorHelpers.SetError(exchange, error, description);

    private static string? ValidateSource(string? kind, string? path, string? constantValue) => kind switch
    {
        "Constant" => string.IsNullOrEmpty(constantValue)
            ? "ConstantValue is required when SourceKind=Constant" : null,
        "CustomClaim" or "UserProps" => string.IsNullOrEmpty(path)
            ? "SourcePath is required when SourceKind=CustomClaim or UserProps" : null,
        null or "" => "SourceKind is required",
        _ => $"Unknown SourceKind '{kind}' (expected: Constant | CustomClaim | UserProps)"
    };

    /// <summary>
    /// Parses the <c>owner</c> string into a parent_id value.
    /// <list type="bullet">
    /// <item><c>null</c> / empty / <c>"global"</c> → <c>null</c> (global rule)</item>
    /// <item><c>application:{id}</c> → application object id</item>
    /// <item><c>scope:{id}</c> → ClaimScope object id</item>
    /// </list>
    /// </summary>
    private static long? ParseOwner(string? owner)
    {
        if (string.IsNullOrWhiteSpace(owner) || owner.Equals("global", StringComparison.OrdinalIgnoreCase))
            return null;

        var sep = owner.IndexOf(':');
        if (sep <= 0)
            throw new FormatException($"Owner '{owner}' must be 'global', 'application:{{id}}' or 'scope:{{id}}'");

        var prefix = owner[..sep].Trim().ToLowerInvariant();
        var rest = owner[(sep + 1)..].Trim();

        if (prefix is not ("application" or "scope"))
            throw new FormatException($"Unknown owner prefix '{prefix}' (expected: application | scope)");

        if (!long.TryParse(rest, out var id) || id <= 0)
            throw new FormatException($"Owner id '{rest}' is not a positive integer");

        return id;
    }

    private static string OwnerString(long? parentId)
        => parentId is null ? "global" : $"id:{parentId.Value}";

    private static ClaimMapperResponse MapToResponse(RedbObject<ClaimMapperProps> obj) => new()
    {
        Id = obj.Id.ToString(),
        Name = obj.Name,
        ClaimType = obj.Props.ClaimType,
        SourceKind = obj.Props.SourceKind,
        SourcePath = obj.Props.SourcePath,
        ConstantValue = obj.Props.ConstantValue,
        RequiredScopes = obj.Props.RequiredScopes,
        Destinations = obj.Props.Destinations,
        Required = obj.Props.Required,
        Order = obj.Props.Order,
        Enabled = obj.Props.Enabled,
        Description = obj.Props.Description,
        Owner = obj.ParentId is null ? "global" : $"id:{obj.ParentId.Value}",
    };
}
