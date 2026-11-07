using redb.Identity.Client.Internal;
using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Webhooks;

namespace redb.Identity.Client;

public partial interface IIdentityClient
{
    Task<PagedResult<WebhookSubscriptionResponse>> ListWebhooksAsync(int offset = 0, int count = 25, CancellationToken ct = default);
    Task<WebhookSubscriptionResponse> GetWebhookAsync(long id, CancellationToken ct = default);
    Task<WebhookSubscriptionResponse> CreateWebhookAsync(CreateWebhookSubscriptionRequest request, CancellationToken ct = default);
    Task UpdateWebhookAsync(long id, UpdateWebhookSubscriptionRequest request, CancellationToken ct = default);
    Task DeleteWebhookAsync(long id, CancellationToken ct = default);
    Task<WebhookSubscriptionResponse> RotateWebhookSecretAsync(long id, CancellationToken ct = default);
}

public sealed partial class IdentityClient
{
    private const string WebhooksBase = "/api/v1/identity/webhooks";

    public async Task<PagedResult<WebhookSubscriptionResponse>> ListWebhooksAsync(int offset = 0, int count = 25, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{WebhooksBase}?offset={offset}&count={count}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<PagedResult<WebhookSubscriptionResponse>>(ct).ConfigureAwait(false);
    }

    public async Task<WebhookSubscriptionResponse> GetWebhookAsync(long id, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{WebhooksBase}/{id}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<WebhookSubscriptionResponse>(ct).ConfigureAwait(false);
    }

    public async Task<WebhookSubscriptionResponse> CreateWebhookAsync(CreateWebhookSubscriptionRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync(WebhooksBase, request, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<WebhookSubscriptionResponse>(ct).ConfigureAwait(false);
    }

    public async Task UpdateWebhookAsync(long id, UpdateWebhookSubscriptionRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PutAsJsonAsync($"{WebhooksBase}/{id}", request, _json, ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
    }

    public async Task DeleteWebhookAsync(long id, CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{WebhooksBase}/{id}", ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
    }

    public async Task<WebhookSubscriptionResponse> RotateWebhookSecretAsync(long id, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{WebhooksBase}/{id}/rotate-secret", new { }, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<WebhookSubscriptionResponse>(ct).ConfigureAwait(false);
    }
}
