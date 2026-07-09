using Microsoft.Extensions.DependencyInjection;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Core.Query;
using redb.Core.Services;
using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Federation;
using redb.Identity.Core.Models;
using redb.Identity.Core.Module;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.RedbCore.Extensions;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// H8 (v1.0 DoD §4 gap (e)): admin CRUD over PROPS-stored
/// <see cref="FederationProviderProps"/>. Operations dispatched on the <c>operation</c>
/// header: <c>create | read | update | delete | list</c>. Client secrets are encrypted
/// at rest via <see cref="FederationProviderSecretProtector"/> and never returned in
/// responses (only <see cref="FederationProviderResponse.HasSecret"/> is exposed).
/// <para>
/// PROPS-stored providers complement (and override) the
/// <c>RedbIdentityOptions.FederationProviders</c> list loaded from <c>appsettings.json</c>:
/// runtime resolution prefers PROPS when both define the same <c>ProviderId</c>, so existing
/// deployments keep working until they migrate to the database.
/// </para>
/// </summary>
internal sealed class FederationProviderManagementProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;

    public FederationProviderManagementProcessor(IRouteContext context, string? redbName = null)
    {
        _context = context;
        _redbName = redbName;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var redb = _context.GetRedbService(_redbName, exchange);
        var protector = _context.GetIdentityService<FederationProviderSecretProtector>(exchange);

        var operation = exchange.In.GetHeader<string>("operation")
            ?? throw new InvalidOperationException("Missing 'operation' header");

        switch (operation)
        {
            case "create": await Create(redb, protector, exchange, ct); break;
            case "read":   await Read(redb, exchange, ct); break;
            case "update": await Update(redb, protector, exchange, ct); break;
            case "delete": await Delete(redb, exchange, ct); break;
            case "list":   await List(redb, exchange, ct); break;
            default:
                SetError(exchange, "invalid_operation", $"Unknown operation: {operation}");
                break;
        }
    }

    private static async Task Create(
        IRedbService redb, FederationProviderSecretProtector protector,
        IExchange exchange, CancellationToken ct)
    {
        var request = exchange.In.Body as CreateFederationProviderRequest;
        if (request is null) { SetError(exchange, "validation_error", "Request body is required"); return; }

        var providerId = request.ProviderId.Trim().ToLowerInvariant();

        // Reject duplicates: value_string is UNIQUE per scheme so a concurrent insert
        // would fail at the DB level anyway, but a friendly error here avoids exposing
        // raw constraint names to the API consumer.
        var dup = await redb.Query<FederationProviderProps>()
            .WhereRedb(o => o.ValueString == providerId)
            .FirstOrDefaultAsync().ConfigureAwait(false);
        if (dup is not null)
        {
            SetError(exchange, "conflict", $"Federation provider '{providerId}' already exists.");
            return;
        }

        var obj = new RedbObject<FederationProviderProps>(new FederationProviderProps
        {
            ProviderId = providerId,
            Kind = request.Kind.Trim().ToLowerInvariant(),
            DisplayName = request.DisplayName.Trim(),
            Authority = request.Authority,
            ClientId = request.ClientId.Trim(),
            EncryptedClientSecret = protector.Protect(request.ClientSecret),
            Scopes = request.Scopes ?? ["openid", "profile", "email"],
            AutoProvision = request.AutoProvision,
            Enabled = request.Enabled,
            Priority = request.Priority,
            ClaimMappings = request.ClaimMappings,
        });
        obj.name = providerId;
        obj.value_string = providerId;

        await redb.SaveAsync(obj).ConfigureAwait(false);

        exchange.Out ??= new Message();
        exchange.Out.Body = MapToResponse(obj);

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.FederationProviderCreated;
        exchange.Properties["identity-event-data"] = new
        {
            Id = obj.Id,
            ProviderId = providerId,
            obj.Props.Kind,
            obj.Props.Enabled,
        };
    }

    private static async Task Read(IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        var id = TryParseId(exchange);
        if (id is null) { SetError(exchange, "validation_error", "Id is required"); return; }

        var obj = await redb.LoadAsync<FederationProviderProps>(id.Value).ConfigureAwait(false);
        if (obj is null) { SetError(exchange, "not_found", $"Federation provider {id} not found"); return; }

        // Restore ProviderId from value_string (it is [RedbIgnore] so not part of props storage)
        obj.Props.ProviderId = obj.value_string ?? string.Empty;

        exchange.Out ??= new Message();
        exchange.Out.Body = MapToResponse(obj);
    }

    private static async Task Update(
        IRedbService redb, FederationProviderSecretProtector protector,
        IExchange exchange, CancellationToken ct)
    {
        var request = exchange.In.Body as UpdateFederationProviderRequest;
        if (request is null || !long.TryParse(request.Id, out var id) || id <= 0)
        { SetError(exchange, "validation_error", "Id is required"); return; }

        var obj = await redb.LoadAsync<FederationProviderProps>(id).ConfigureAwait(false);
        if (obj is null) { SetError(exchange, "not_found", $"Federation provider {id} not found"); return; }

        obj.Props.ProviderId = obj.value_string ?? string.Empty;

        if (request.Kind != null) obj.Props.Kind = request.Kind.Trim().ToLowerInvariant();
        if (request.DisplayName != null) obj.Props.DisplayName = request.DisplayName.Trim();
        if (request.Authority != null) obj.Props.Authority = request.Authority;
        if (request.ClientId != null) obj.Props.ClientId = request.ClientId.Trim();
        if (request.ClientSecret != null)
        {
            // Empty string ⇒ clear; non-empty ⇒ rotate. Null was already filtered above.
            obj.Props.EncryptedClientSecret = string.IsNullOrEmpty(request.ClientSecret)
                ? null : protector.Protect(request.ClientSecret);
        }
        if (request.Scopes != null) obj.Props.Scopes = request.Scopes;
        if (request.AutoProvision.HasValue) obj.Props.AutoProvision = request.AutoProvision.Value;
        if (request.Enabled.HasValue) obj.Props.Enabled = request.Enabled.Value;
        if (request.Priority.HasValue) obj.Props.Priority = request.Priority.Value;
        if (request.ClaimMappings != null) obj.Props.ClaimMappings = request.ClaimMappings;

        await redb.SaveAsync(obj).ConfigureAwait(false);

        exchange.Out ??= new Message();
        exchange.Out.Body = MapToResponse(obj);

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.FederationProviderUpdated;
        exchange.Properties["identity-event-data"] = new { Id = id, obj.Props.ProviderId };
    }

    private async Task Delete(IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        var id = TryParseId(exchange);
        if (id is null) { SetError(exchange, "validation_error", "Id is required"); return; }

        var obj = await redb.LoadAsync<FederationProviderProps>(id.Value).ConfigureAwait(false);
        if (obj is null) { SetError(exchange, "not_found", $"Federation provider {id} not found"); return; }

        var providerId = obj.value_string ?? string.Empty;

        // Note: deleting a provider does NOT cascade-delete user FederatedIdentityProps
        // links — those become "orphaned" but the user can still log in if the same
        // ProviderId is re-created or remains in appsettings. This matches Keycloak's
        // behavior (provider deletion does not log users out).
        var bg = _context.GetIdentityServiceOrDefault<IBackgroundDeletionService>(exchange);
        await IdentityDeletionHelper.DeleteAsync(redb, bg, id.Value).ConfigureAwait(false);

        exchange.Out ??= new Message();
        exchange.Out.Body = new { success = true };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.FederationProviderDeleted;
        exchange.Properties["identity-event-data"] = new { Id = id, ProviderId = providerId };
    }

    private static async Task List(IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        var request = exchange.In.Body as ListRequest ?? new ListRequest();

        var query = redb.Query<FederationProviderProps>().OrderByRedb(o => o.Id);
        var total = await query.CountAsync().ConfigureAwait(false);
        var count = Math.Min(request.Count, 100);
        var items = await query.Skip(request.Offset).Take(count).ToListAsync().ConfigureAwait(false);

        // Restore [RedbIgnore] ProviderId from value_string before mapping.
        foreach (var item in items)
            item.Props.ProviderId = item.value_string ?? string.Empty;

        exchange.Out ??= new Message();
        exchange.Out.Body = new PagedResult<FederationProviderResponse>
        {
            Items = items.Select(MapToResponse).ToList(),
            Total = total,
            Offset = request.Offset,
            Count = request.Count,
        };
    }

    private static long? TryParseId(IExchange exchange)
    {
        if (exchange.In.Body is not Dictionary<string, object?> dict
            || !dict.TryGetValue("id", out var idVal) || idVal == null
            || !long.TryParse(idVal.ToString(), out var id) || id <= 0)
            return null;
        return id;
    }

    private static void SetError(IExchange exchange, string error, string description)
        => IdentityProcessorHelpers.SetError(exchange, error, description);

    private static FederationProviderResponse MapToResponse(RedbObject<FederationProviderProps> obj) => new()
    {
        Id = obj.Id.ToString(),
        ProviderId = obj.Props.ProviderId,
        Kind = obj.Props.Kind,
        DisplayName = obj.Props.DisplayName,
        Authority = obj.Props.Authority,
        ClientId = obj.Props.ClientId,
        HasSecret = !string.IsNullOrEmpty(obj.Props.EncryptedClientSecret),
        Scopes = obj.Props.Scopes,
        AutoProvision = obj.Props.AutoProvision,
        Enabled = obj.Props.Enabled,
        Priority = obj.Props.Priority,
        ClaimMappings = obj.Props.ClaimMappings,
    };
}
