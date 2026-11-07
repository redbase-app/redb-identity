using redb.Identity.Client.Internal;
using redb.Identity.Contracts.ClaimDefinitions;
using redb.Identity.Contracts.Common;

namespace redb.Identity.Client;

public partial interface IIdentityClient
{
    Task<PagedResult<ClaimDefinitionResponse>> ListClaimDefinitionsAsync(int offset = 0, int count = 50, string? scope = null, long? applicationId = null, CancellationToken ct = default);
    Task<ClaimDefinitionResponse> GetClaimDefinitionAsync(long id, CancellationToken ct = default);
    Task<ClaimDefinitionResponse> CreateClaimDefinitionAsync(CreateClaimDefinitionRequest request, CancellationToken ct = default);
    Task<ClaimDefinitionResponse> UpdateClaimDefinitionAsync(long id, UpdateClaimDefinitionRequest request, CancellationToken ct = default);
    Task DeleteClaimDefinitionAsync(long id, CancellationToken ct = default);
}

public sealed partial class IdentityClient
{
    private const string ClaimDefinitionsBase = "/api/v1/identity/claim-definitions";

    public async Task<PagedResult<ClaimDefinitionResponse>> ListClaimDefinitionsAsync(
        int offset = 0, int count = 50, string? scope = null, long? applicationId = null,
        CancellationToken ct = default)
    {
        var url = $"{ClaimDefinitionsBase}?offset={offset}&count={count}";
        if (!string.IsNullOrEmpty(scope)) url += $"&scope={Uri.EscapeDataString(scope)}";
        if (applicationId.HasValue) url += $"&applicationId={applicationId.Value}";
        using var resp = await _http.GetAsync(url, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<PagedResult<ClaimDefinitionResponse>>(ct).ConfigureAwait(false);
    }

    public async Task<ClaimDefinitionResponse> GetClaimDefinitionAsync(long id, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{ClaimDefinitionsBase}/{id}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<ClaimDefinitionResponse>(ct).ConfigureAwait(false);
    }

    public async Task<ClaimDefinitionResponse> CreateClaimDefinitionAsync(CreateClaimDefinitionRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync(ClaimDefinitionsBase, request, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<ClaimDefinitionResponse>(ct).ConfigureAwait(false);
    }

    public async Task<ClaimDefinitionResponse> UpdateClaimDefinitionAsync(long id, UpdateClaimDefinitionRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PutAsJsonAsync($"{ClaimDefinitionsBase}/{id}", request, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<ClaimDefinitionResponse>(ct).ConfigureAwait(false);
    }

    public async Task DeleteClaimDefinitionAsync(long id, CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{ClaimDefinitionsBase}/{id}", ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
    }
}
