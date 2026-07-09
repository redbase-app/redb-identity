using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Routes;
using redb.Identity.Contracts.Webhooks;
using redb.Route.Controllers.Attributes;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// W1 — REST admin API for outbound webhook subscriptions.
/// Forwards to <c>direct-vm://identity-manage-webhooks</c>.
/// </summary>
[Route("webhooks")]
public class WebhooksController : IdentityControllerBase
{
    [HttpGet]
    public async Task<object?> List(
        [FromQuery("offset")] int offset = 0,
        [FromQuery("count")] int count = 25)
    {
        return await Forward(IdentityEndpoints.ManageWebhooks, "list",
            new ListRequest { Offset = offset, Count = count });
    }

    [HttpGet("{id}")]
    public async Task<object?> Get([FromRoute("id")] string id)
    {
        return await Forward(IdentityEndpoints.ManageWebhooks, "get",
            new Dictionary<string, object> { ["id"] = id });
    }

    [HttpPost]
    public async Task<object?> Create([FromBody] CreateWebhookSubscriptionRequest request)
    {
        if (ValidateRequest(request) is { } problem) return problem;
        return await Forward(IdentityEndpoints.ManageWebhooks, "create", request);
    }

    [HttpPut("{id}")]
    public async Task<object?> Update(
        [FromRoute("id")] string id,
        [FromBody] UpdateWebhookSubscriptionRequest request)
    {
        var body = new Dictionary<string, object?>
        {
            ["id"] = id,
            ["displayName"] = request.DisplayName,
            ["description"] = request.Description,
            ["url"] = request.Url,
            ["eventTypeFilter"] = request.EventTypeFilter,
            ["enabled"] = request.Enabled,
            ["timeoutMs"] = request.TimeoutMs,
            ["maxAttempts"] = request.MaxAttempts,
            ["retryBackoffMs"] = request.RetryBackoffMs,
            ["extraHeaders"] = request.ExtraHeaders,
        };
        return await Forward(IdentityEndpoints.ManageWebhooks, "update", body);
    }

    [HttpDelete("{id}")]
    public async Task<object?> Delete([FromRoute("id")] string id)
    {
        return await Forward(IdentityEndpoints.ManageWebhooks, "delete",
            new Dictionary<string, object> { ["id"] = id });
    }

    [HttpPost("{id}/rotate-secret")]
    public async Task<object?> RotateSecret([FromRoute("id")] string id)
    {
        return await Forward(IdentityEndpoints.ManageWebhooks, "rotate-secret",
            new Dictionary<string, object> { ["id"] = id });
    }
}
