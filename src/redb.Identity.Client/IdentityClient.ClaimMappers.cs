using redb.Identity.Contracts.ClaimMappers;
using redb.Identity.Contracts.Common;

namespace redb.Identity.Client;

public partial interface IIdentityClient
{
    // ── Claim mappers ──
    Task<PagedResult<ClaimMapperResponse>> ListClaimMappersAsync(string? owner = null, int offset = 0, int count = 25, CancellationToken ct = default);
    Task<ClaimMapperResponse> GetClaimMapperAsync(string id, CancellationToken ct = default);
    Task<ClaimMapperResponse> CreateClaimMapperAsync(CreateClaimMapperRequest request, CancellationToken ct = default);
    Task<ClaimMapperResponse> UpdateClaimMapperAsync(string id, UpdateClaimMapperRequest request, CancellationToken ct = default);
    Task DeleteClaimMapperAsync(string id, CancellationToken ct = default);

    // ── Claim scopes (mapper bundles) ──
    Task<PagedResult<ClaimScopeResponse>> ListClaimScopesAsync(int offset = 0, int count = 25, CancellationToken ct = default);
    Task<ClaimScopeResponse> GetClaimScopeAsync(string id, CancellationToken ct = default);
    Task<ClaimScopeResponse> CreateClaimScopeAsync(CreateClaimScopeRequest request, CancellationToken ct = default);
    Task<ClaimScopeResponse> UpdateClaimScopeAsync(string id, UpdateClaimScopeRequest request, CancellationToken ct = default);
    Task DeleteClaimScopeAsync(string id, CancellationToken ct = default);

    // ── Application ↔ Scope assignments ──
    Task<System.Text.Json.JsonElement> ListClaimScopeAssignmentsAsync(string applicationId, CancellationToken ct = default);
    Task<System.Text.Json.JsonElement> AssignClaimScopeAsync(AssignClaimScopeRequest request, CancellationToken ct = default);
    Task UnassignClaimScopeAsync(string applicationId, string scopeId, CancellationToken ct = default);
}

public sealed partial class IdentityClient
{
    private const string ClaimMappersBase = "/api/v1/identity/claim-mappers";
    private const string ClaimScopesBase = "/api/v1/identity/claim-scopes";

    public async Task<PagedResult<ClaimMapperResponse>> ListClaimMappersAsync(string? owner = null, int offset = 0, int count = 25, CancellationToken ct = default)
    {
        var url = $"{ClaimMappersBase}?offset={offset}&count={count}"
            + (owner is null ? "" : $"&owner={Uri.EscapeDataString(owner)}");
        using var resp = await _http.GetAsync(url, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<PagedResult<ClaimMapperResponse>>(ct).ConfigureAwait(false);
    }

    public async Task<ClaimMapperResponse> GetClaimMapperAsync(string id, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{ClaimMappersBase}/{Uri.EscapeDataString(id)}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<ClaimMapperResponse>(ct).ConfigureAwait(false);
    }

    public async Task<ClaimMapperResponse> CreateClaimMapperAsync(CreateClaimMapperRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync(ClaimMappersBase, request, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<ClaimMapperResponse>(ct).ConfigureAwait(false);
    }

    public async Task<ClaimMapperResponse> UpdateClaimMapperAsync(string id, UpdateClaimMapperRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PutAsJsonAsync($"{ClaimMappersBase}/{Uri.EscapeDataString(id)}", request, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<ClaimMapperResponse>(ct).ConfigureAwait(false);
    }

    public async Task DeleteClaimMapperAsync(string id, CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{ClaimMappersBase}/{Uri.EscapeDataString(id)}", ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
    }

    // ── Claim scopes ──

    public async Task<PagedResult<ClaimScopeResponse>> ListClaimScopesAsync(int offset = 0, int count = 25, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{ClaimScopesBase}?offset={offset}&count={count}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<PagedResult<ClaimScopeResponse>>(ct).ConfigureAwait(false);
    }

    public async Task<ClaimScopeResponse> GetClaimScopeAsync(string id, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{ClaimScopesBase}/{Uri.EscapeDataString(id)}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<ClaimScopeResponse>(ct).ConfigureAwait(false);
    }

    public async Task<ClaimScopeResponse> CreateClaimScopeAsync(CreateClaimScopeRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync(ClaimScopesBase, request, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<ClaimScopeResponse>(ct).ConfigureAwait(false);
    }

    public async Task<ClaimScopeResponse> UpdateClaimScopeAsync(string id, UpdateClaimScopeRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PutAsJsonAsync($"{ClaimScopesBase}/{Uri.EscapeDataString(id)}", request, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<ClaimScopeResponse>(ct).ConfigureAwait(false);
    }

    public async Task DeleteClaimScopeAsync(string id, CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{ClaimScopesBase}/{Uri.EscapeDataString(id)}", ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
    }

    // ── Application ↔ Scope assignments ──

    public async Task<System.Text.Json.JsonElement> ListClaimScopeAssignmentsAsync(string applicationId, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{ClaimScopesBase}/assignments?applicationId={Uri.EscapeDataString(applicationId)}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<System.Text.Json.JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<System.Text.Json.JsonElement> AssignClaimScopeAsync(AssignClaimScopeRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{ClaimScopesBase}/assignments", request, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<System.Text.Json.JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task UnassignClaimScopeAsync(string applicationId, string scopeId, CancellationToken ct = default)
    {
        var url = $"{ClaimScopesBase}/assignments?applicationId={Uri.EscapeDataString(applicationId)}&scopeId={Uri.EscapeDataString(scopeId)}";
        using var resp = await _http.DeleteAsync(url, ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
    }
}
