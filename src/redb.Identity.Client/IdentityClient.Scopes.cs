using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Scopes;

namespace redb.Identity.Client;

public partial interface IIdentityClient
{
    Task<PagedResult<ScopeResponse>> ListScopesAsync(int offset = 0, int count = 25, CancellationToken ct = default);
    Task<ScopeResponse> GetScopeAsync(string id, CancellationToken ct = default);
    Task<ScopeResponse> CreateScopeAsync(CreateScopeRequest request, CancellationToken ct = default);
    Task<ScopeResponse> UpdateScopeAsync(string id, UpdateScopeRequest request, CancellationToken ct = default);
    Task DeleteScopeAsync(string id, CancellationToken ct = default);
}

public sealed partial class IdentityClient
{
    private const string ScopesBase = "/api/v1/identity/scopes";

    public async Task<PagedResult<ScopeResponse>> ListScopesAsync(int offset = 0, int count = 25, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{ScopesBase}?offset={offset}&count={count}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<PagedResult<ScopeResponse>>(ct).ConfigureAwait(false);
    }

    public async Task<ScopeResponse> GetScopeAsync(string id, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{ScopesBase}/{Uri.EscapeDataString(id)}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<ScopeResponse>(ct).ConfigureAwait(false);
    }

    public async Task<ScopeResponse> CreateScopeAsync(CreateScopeRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync(ScopesBase, request, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<ScopeResponse>(ct).ConfigureAwait(false);
    }

    public async Task<ScopeResponse> UpdateScopeAsync(string id, UpdateScopeRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PutAsJsonAsync($"{ScopesBase}/{Uri.EscapeDataString(id)}", request, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<ScopeResponse>(ct).ConfigureAwait(false);
    }

    public async Task DeleteScopeAsync(string id, CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{ScopesBase}/{Uri.EscapeDataString(id)}", ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
    }
}
