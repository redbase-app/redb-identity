using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Core.Query;
using redb.Identity.Contracts.ClaimDefinitions;
using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Routes;
using redb.Identity.Core.Models;
using redb.Identity.Core.Module;
using redb.Route.Abstractions;
using redb.Route.RedbCore.Extensions;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// S2 — admin CRUD for claim definitions. Routes via
/// <see cref="IdentityEndpoints.ManageClaimDefinitions"/> with the same
/// operation-header convention every other admin processor uses
/// (create / list / get / update / delete).
///
/// <para>
/// Validation:
///   * (ClaimName, Scope, ApplicationId) triplet must be unique.
///   * Type must be one of the supported tokens (string / int / long / bool /
///     datetime / url / email).
///   * Scope = "application" requires a non-null ApplicationId; Scope =
///     "global" requires ApplicationId = null.
/// </para>
/// </summary>
internal sealed class ClaimDefinitionsManagementProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;
    private readonly ILogger<ClaimDefinitionsManagementProcessor> _logger;

    private static readonly HashSet<string> AllowedTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "string", "int", "long", "bool", "datetime", "url", "email"
    };

    public ClaimDefinitionsManagementProcessor(IRouteContext context, string? redbName, ILogger<ClaimDefinitionsManagementProcessor> logger)
    {
        _context = context;
        _redbName = redbName;
        _logger = logger;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var operation = exchange.In.GetHeader<string>("operation") ?? "";
        var redb = _context.GetRedbService(_redbName, exchange);

        switch (operation)
        {
            case "create":
                await Create(redb, exchange, ct);
                break;
            case "list":
                await List(redb, exchange, ct);
                break;
            case "get":
                await Get(redb, exchange, ct);
                break;
            case "update":
                await Update(redb, exchange, ct);
                break;
            case "delete":
                await Delete(redb, exchange, ct);
                break;
            default:
                exchange.Out ??= new redb.Route.Core.Message();
                exchange.Out.Body = new { error = "invalid_operation", error_description = $"Unknown operation: {operation}" };
                break;
        }
    }

    private async Task Create(IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        if (exchange.In.Body is not CreateClaimDefinitionRequest request)
        {
            SetError(exchange, "validation_error", "Body must be a CreateClaimDefinitionRequest");
            return;
        }

        var claimName = request.ClaimName?.Trim() ?? "";
        if (string.IsNullOrEmpty(claimName))
        {
            SetError(exchange, "validation_error", "claimName is required");
            return;
        }

        if (!AllowedTypes.Contains(request.Type))
        {
            SetError(exchange, "validation_error", $"type must be one of: {string.Join(", ", AllowedTypes)}");
            return;
        }

        if (request.Scope is not ("global" or "application"))
        {
            SetError(exchange, "validation_error", "scope must be 'global' or 'application'");
            return;
        }

        if (request.Scope == "application" && (request.ApplicationId is null or 0))
        {
            SetError(exchange, "validation_error", "scope='application' requires a non-null applicationId");
            return;
        }
        if (request.Scope == "global" && request.ApplicationId is not null)
        {
            SetError(exchange, "validation_error", "scope='global' requires applicationId to be null");
            return;
        }

        // Uniqueness check — (ClaimName, Scope, ApplicationId)
        var dupe = await redb.Query<ClaimDefinitionProps>()
            .Where(p => p.ClaimName == claimName)
            .Where(p => p.Scope == request.Scope)
            .Where(p => p.ApplicationId == request.ApplicationId)
            .FirstOrDefaultAsync();
        if (dupe is not null)
        {
            SetError(exchange, "conflict",
                $"A definition for claimName='{claimName}' with the same scope already exists (id={dupe.Id})");
            return;
        }

        var obj = new RedbObject<ClaimDefinitionProps>
        {
            name = claimName,
            Props = new ClaimDefinitionProps
            {
                ClaimName = claimName,
                DisplayName = string.IsNullOrWhiteSpace(request.DisplayName) ? null : request.DisplayName.Trim(),
                Description = request.Description,
                Type = request.Type,
                Required = request.Required,
                DefaultValue = request.DefaultValue,
                ValidationPattern = request.ValidationPattern,
                Scope = request.Scope,
                ApplicationId = request.ApplicationId,
                EmitOnIdToken = request.EmitOnIdToken,
                EmitOnAccessToken = request.EmitOnAccessToken,
            }
        };
        obj.id = await redb.SaveAsync(obj);

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = MapToResponse(obj);
    }

    private async Task List(IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        var request = exchange.In.Body as ListRequest ?? new ListRequest();
        var count = Math.Min(request.Count, 200);

        // Optional filter — scope or applicationId from the body dict shape.
        string? scopeFilter = null;
        long? appIdFilter = null;
        if (exchange.In.Body is Dictionary<string, object?> dict)
        {
            if (dict.TryGetValue("scope", out var s) && s is string sStr && !string.IsNullOrEmpty(sStr))
                scopeFilter = sStr;
            if (dict.TryGetValue("applicationId", out var a) && a is not null
                && long.TryParse(a.ToString(), out var parsedApp))
                appIdFilter = parsedApp;
        }

        var q = redb.Query<ClaimDefinitionProps>();
        if (scopeFilter is not null) q = q.Where(p => p.Scope == scopeFilter);
        if (appIdFilter is not null) q = q.Where(p => p.ApplicationId == appIdFilter);

        var total = await q.CountAsync();
        var items = await q
            .Skip(request.Offset)
            .Take(count)
            .ToListAsync();

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new PagedResult<ClaimDefinitionResponse>
        {
            Items = items.Select(MapToResponse).ToList(),
            Total = total,
            Offset = request.Offset,
            Count = request.Count
        };
    }

    private async Task Get(IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        if (exchange.In.Body is not Dictionary<string, object?> dict
            || !dict.TryGetValue("id", out var idVal)
            || !long.TryParse(idVal?.ToString(), out var id) || id <= 0)
        {
            SetError(exchange, "validation_error", "id is required");
            return;
        }

        var obj = await redb.LoadAsync<ClaimDefinitionProps>(id);
        if (obj is null)
        {
            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = new { error = "not_found", error_description = $"ClaimDefinition {id} not found" };
            return;
        }

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = MapToResponse(obj);
    }

    private async Task Update(IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        if (exchange.In.Body is not UpdateClaimDefinitionRequest request || request.Id <= 0)
        {
            SetError(exchange, "validation_error", "id is required");
            return;
        }

        var obj = await redb.LoadAsync<ClaimDefinitionProps>(request.Id);
        if (obj is null)
        {
            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = new { error = "not_found", error_description = $"ClaimDefinition {request.Id} not found" };
            return;
        }

        if (request.Type is not null)
        {
            if (!AllowedTypes.Contains(request.Type))
            {
                SetError(exchange, "validation_error", $"type must be one of: {string.Join(", ", AllowedTypes)}");
                return;
            }
            obj.Props.Type = request.Type;
        }
        if (request.DisplayName is not null) obj.Props.DisplayName = string.IsNullOrWhiteSpace(request.DisplayName) ? null : request.DisplayName.Trim();
        if (request.Description is not null) obj.Props.Description = request.Description;
        if (request.Required.HasValue) obj.Props.Required = request.Required.Value;
        if (request.DefaultValue is not null) obj.Props.DefaultValue = request.DefaultValue;
        if (request.ValidationPattern is not null) obj.Props.ValidationPattern = request.ValidationPattern;
        if (request.EmitOnIdToken.HasValue) obj.Props.EmitOnIdToken = request.EmitOnIdToken.Value;
        if (request.EmitOnAccessToken.HasValue) obj.Props.EmitOnAccessToken = request.EmitOnAccessToken.Value;

        await redb.SaveAsync(obj);

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = MapToResponse(obj);
    }

    private async Task Delete(IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        if (exchange.In.Body is not Dictionary<string, object?> dict
            || !dict.TryGetValue("id", out var idVal)
            || !long.TryParse(idVal?.ToString(), out var id) || id <= 0)
        {
            SetError(exchange, "validation_error", "id is required");
            return;
        }

        await redb.DeleteAsync(new RedbObject<ClaimDefinitionProps> { id = id });

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new { success = true };
    }

    private static ClaimDefinitionResponse MapToResponse(RedbObject<ClaimDefinitionProps> obj) => new()
    {
        Id = obj.Id,
        ClaimName = obj.Props.ClaimName,
        DisplayName = obj.Props.DisplayName,
        Description = obj.Props.Description,
        Type = obj.Props.Type,
        Required = obj.Props.Required,
        DefaultValue = obj.Props.DefaultValue,
        ValidationPattern = obj.Props.ValidationPattern,
        Scope = obj.Props.Scope,
        ApplicationId = obj.Props.ApplicationId,
        EmitOnIdToken = obj.Props.EmitOnIdToken,
        EmitOnAccessToken = obj.Props.EmitOnAccessToken,
        CreatedAt = obj.date_create,
        ModifiedAt = obj.date_modify,
    };

    private static void SetError(IExchange exchange, string code, string description)
    {
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new { error = code, error_description = description };
    }
}
