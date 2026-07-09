using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Routes;
using redb.Identity.Contracts.Webhooks;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.RedbCore.Extensions;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// W1 — admin CRUD for outbound webhook subscriptions. Operations:
///   list / get / create / update / delete / rotate-secret.
///
/// HMAC secret is included ONLY on the create + rotate-secret responses.
/// All other responses omit it; the existence flag <c>HasHmacSecret</c>
/// surfaces presence without leaking the value.
/// </summary>
internal sealed class WebhookManagementProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;
    private readonly ILogger<WebhookManagementProcessor> _logger;

    public WebhookManagementProcessor(IRouteContext context, string? redbName, ILogger<WebhookManagementProcessor> logger)
    {
        _context = context;
        _redbName = redbName;
        _logger = logger;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var operation = exchange.In.GetHeader<string>("operation") ?? "";
        var redb = _context.GetRedbService(_redbName, exchange);
        var svc = new WebhookSubscriptionService(redb);

        switch (operation)
        {
            case "list":           await List(svc, exchange, ct); break;
            case "get":            await Get(svc, exchange, ct); break;
            case "create":         await Create(svc, exchange, ct); break;
            case "update":         await Update(svc, exchange, ct); break;
            case "delete":         await Delete(svc, exchange, ct); break;
            case "rotate-secret":  await RotateSecret(svc, exchange, ct); break;
            default:
                SetError(exchange, "invalid_operation", $"Unknown operation: {operation}");
                break;
        }
    }

    private async Task List(WebhookSubscriptionService svc, IExchange exchange, CancellationToken ct)
    {
        var request = exchange.In.Body as ListRequest ?? new ListRequest();
        var offset = Math.Max(0, request.Offset);
        var count = Math.Clamp(request.Count, 1, 200);

        var items = await svc.ListAsync(offset, count, ct).ConfigureAwait(false);
        var total = await svc.CountAsync(ct).ConfigureAwait(false);

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new PagedResult<WebhookSubscriptionResponse>
        {
            Items = items.Select(o => MapToResponse(o, includeSecret: false)).ToList(),
            Total = total,
            Offset = offset,
            Count = count
        };
    }

    private async Task Get(WebhookSubscriptionService svc, IExchange exchange, CancellationToken ct)
    {
        var id = ExtractLongFromBody(exchange, "id");
        if (id is null) { SetError(exchange, "validation_error", "id is required"); return; }
        var obj = await svc.GetAsync(id.Value, ct).ConfigureAwait(false);
        if (obj is null) { SetError(exchange, "not_found", $"Webhook {id} not found"); return; }

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = MapToResponse(obj, includeSecret: false);
    }

    private async Task Create(WebhookSubscriptionService svc, IExchange exchange, CancellationToken ct)
    {
        if (exchange.In.Body is not CreateWebhookSubscriptionRequest request)
        {
            SetError(exchange, "validation_error", "Body must be a CreateWebhookSubscriptionRequest");
            return;
        }

        try
        {
            var created = await svc.CreateAsync(
                url: request.Url,
                displayName: request.DisplayName,
                description: request.Description,
                eventTypeFilter: request.EventTypeFilter,
                enabled: request.Enabled ?? true,
                timeoutMs: request.TimeoutMs ?? 5000,
                maxAttempts: request.MaxAttempts ?? 3,
                retryBackoffMs: request.RetryBackoffMs ?? 500,
                extraHeaders: request.ExtraHeaders,
                hmacSecret: request.HmacSecret,
                ct: ct).ConfigureAwait(false);

            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = MapToResponse(created, includeSecret: true);

            exchange.Properties["identity-event-type"] = IdentityAuditEventIds.WebhookSubscriptionCreated;
            exchange.Properties["identity-event-data"] = new { WebhookId = created.Id, Url = created.Props.Url };
        }
        catch (ArgumentException ex)
        {
            SetError(exchange, "validation_error", ex.Message);
        }
    }

    private async Task Update(WebhookSubscriptionService svc, IExchange exchange, CancellationToken ct)
    {
        var id = ExtractLongFromBody(exchange, "id");
        if (id is null) { SetError(exchange, "validation_error", "id is required"); return; }
        if (exchange.In.Body is not UpdateWebhookSubscriptionRequest request)
        {
            SetError(exchange, "validation_error", "Body must be an UpdateWebhookSubscriptionRequest");
            return;
        }

        try
        {
            await svc.UpdateAsync(
                id.Value,
                request.DisplayName, request.Description, request.Url, request.EventTypeFilter,
                request.Enabled, request.TimeoutMs, request.MaxAttempts, request.RetryBackoffMs,
                request.ExtraHeaders,
                ct).ConfigureAwait(false);

            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = new { success = true };

            exchange.Properties["identity-event-type"] = IdentityAuditEventIds.WebhookSubscriptionUpdated;
            exchange.Properties["identity-event-data"] = new { WebhookId = id.Value };
        }
        catch (ArgumentException ex)
        {
            SetError(exchange, "validation_error", ex.Message);
        }
        catch (InvalidOperationException ex)
        {
            SetError(exchange, "not_found", ex.Message);
        }
    }

    private async Task Delete(WebhookSubscriptionService svc, IExchange exchange, CancellationToken ct)
    {
        var id = ExtractLongFromBody(exchange, "id");
        if (id is null) { SetError(exchange, "validation_error", "id is required"); return; }
        await svc.DeleteAsync(id.Value, ct).ConfigureAwait(false);

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new { success = true };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.WebhookSubscriptionDeleted;
        exchange.Properties["identity-event-data"] = new { WebhookId = id.Value };
    }

    private async Task RotateSecret(WebhookSubscriptionService svc, IExchange exchange, CancellationToken ct)
    {
        var id = ExtractLongFromBody(exchange, "id");
        if (id is null) { SetError(exchange, "validation_error", "id is required"); return; }
        try
        {
            var newSecret = await svc.RotateSecretAsync(id.Value, ct).ConfigureAwait(false);
            var obj = await svc.GetAsync(id.Value, ct).ConfigureAwait(false);
            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = obj is null
                ? new { success = true, hmacSecret = newSecret }
                : MapToResponse(obj, includeSecret: true);

            exchange.Properties["identity-event-type"] = IdentityAuditEventIds.WebhookSubscriptionSecretRotated;
            exchange.Properties["identity-event-data"] = new { WebhookId = id.Value };
        }
        catch (InvalidOperationException ex)
        {
            SetError(exchange, "not_found", ex.Message);
        }
    }

    private static long? ExtractLongFromBody(IExchange exchange, string field)
    {
        if (exchange.In.Body is not Dictionary<string, object?> dict) return null;
        if (!dict.TryGetValue(field, out var v) || v is null) return null;
        return long.TryParse(v.ToString(), out var parsed) ? parsed : null;
    }

    private static WebhookSubscriptionResponse MapToResponse(
        redb.Core.Models.Entities.RedbObject<WebhookSubscriptionProps> obj, bool includeSecret) => new()
    {
        Id = obj.Id,
        DisplayName = obj.Props.DisplayName,
        Description = obj.Props.Description,
        Url = obj.Props.Url,
        EventTypeFilter = obj.Props.EventTypeFilter,
        Enabled = obj.Props.Enabled,
        TimeoutMs = obj.Props.TimeoutMs,
        MaxAttempts = obj.Props.MaxAttempts,
        RetryBackoffMs = obj.Props.RetryBackoffMs,
        ExtraHeaders = obj.Props.ExtraHeaders,
        HmacSecret = includeSecret ? obj.Props.HmacSecret : null,
        HasHmacSecret = !string.IsNullOrEmpty(obj.Props.HmacSecret),
        CreatedAt = obj.date_create,
        ModifiedAt = obj.date_modify
    };

    private static void SetError(IExchange exchange, string code, string description)
    {
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new { error = code, error_description = description };
    }
}
