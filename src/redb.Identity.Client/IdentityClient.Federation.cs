using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Federation;

namespace redb.Identity.Client;

public partial interface IIdentityClient
{
    Task<PagedResult<FederationProviderResponse>> ListFederationProvidersAsync(int offset = 0, int count = 25, CancellationToken ct = default);
    Task<FederationProviderResponse> GetFederationProviderAsync(string id, CancellationToken ct = default);
    Task<FederationProviderResponse> CreateFederationProviderAsync(CreateFederationProviderRequest request, CancellationToken ct = default);
    Task<FederationProviderResponse> UpdateFederationProviderAsync(string id, UpdateFederationProviderRequest request, CancellationToken ct = default);
    Task DeleteFederationProviderAsync(string id, CancellationToken ct = default);

    /// <summary>
    /// Returns the public projection of configured federation providers (anonymous —
    /// safe for unauthenticated login pages). Strips <c>ClientSecret</c>, <c>Authority</c>,
    /// scope list and other secret/configuration fields. Carries only <c>ProviderId</c>,
    /// <c>DisplayName</c>, <c>Kind</c> and <c>Priority</c> — enough to render a sign-in button.
    /// </summary>
    Task<IReadOnlyList<PublicFederationProviderDescriptor>> ListPublicFederationProvidersAsync(CancellationToken ct = default);
}

public sealed partial class IdentityClient
{
    private const string FederationBase = "/api/v1/identity/federation-providers";

    public async Task<PagedResult<FederationProviderResponse>> ListFederationProvidersAsync(int offset = 0, int count = 25, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{FederationBase}?offset={offset}&count={count}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<PagedResult<FederationProviderResponse>>(ct).ConfigureAwait(false);
    }

    public async Task<FederationProviderResponse> GetFederationProviderAsync(string id, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{FederationBase}/{Uri.EscapeDataString(id)}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<FederationProviderResponse>(ct).ConfigureAwait(false);
    }

    public async Task<FederationProviderResponse> CreateFederationProviderAsync(CreateFederationProviderRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync(FederationBase, request, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<FederationProviderResponse>(ct).ConfigureAwait(false);
    }

    public async Task<FederationProviderResponse> UpdateFederationProviderAsync(string id, UpdateFederationProviderRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PutAsJsonAsync($"{FederationBase}/{Uri.EscapeDataString(id)}", request, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<FederationProviderResponse>(ct).ConfigureAwait(false);
    }

    public async Task DeleteFederationProviderAsync(string id, CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{FederationBase}/{Uri.EscapeDataString(id)}", ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
    }

    /// <inheritdoc cref="IIdentityClient.ListPublicFederationProvidersAsync"/>
    public async Task<IReadOnlyList<PublicFederationProviderDescriptor>> ListPublicFederationProvidersAsync(CancellationToken ct = default)
    {
        // No Authorization header is sent for this call (uses _http baseline; the public
        // endpoint is allow-anonymous). Callers that have a bearer token attached at the
        // HttpClient level will still succeed — the endpoint simply ignores it.
        using var resp = await _http.GetAsync($"{FederationBase}/public", ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
        var list = await resp.Content
            .ReadFromJsonAsync<List<PublicFederationProviderDescriptor>>(_json, ct)
            .ConfigureAwait(false);
        return (IReadOnlyList<PublicFederationProviderDescriptor>?)list
            ?? Array.Empty<PublicFederationProviderDescriptor>();
    }
}
