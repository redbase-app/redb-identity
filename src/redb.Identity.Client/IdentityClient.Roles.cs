using redb.Identity.Client.Internal;
using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Roles;

namespace redb.Identity.Client;

public partial interface IIdentityClient
{
    Task<PagedResult<RoleResponse>> SearchRolesAsync(
        string? query = null, string? audience = null, long? applicationId = null,
        int offset = 0, int count = 25, CancellationToken ct = default);
    Task<RoleResponse> GetRoleAsync(long id, CancellationToken ct = default);
    Task<RoleResponse> CreateRoleAsync(CreateRoleRequest request, CancellationToken ct = default);
    Task UpdateRoleAsync(long id, UpdateRoleRequest request, CancellationToken ct = default);
    Task DeleteRoleAsync(long id, CancellationToken ct = default);

    Task<IReadOnlyList<RoleAssignmentResponse>> ListRoleAssigneesAsync(long roleId, CancellationToken ct = default);
    Task AssignUserToRoleAsync(long roleId, long userId, CancellationToken ct = default);
    Task UnassignUserFromRoleAsync(long roleId, long userId, CancellationToken ct = default);
    Task AssignGroupToRoleAsync(long roleId, long groupId, CancellationToken ct = default);
    Task UnassignGroupFromRoleAsync(long roleId, long groupId, CancellationToken ct = default);

    Task<IReadOnlyList<RoleScopeResponse>> ListRoleScopesAsync(long roleId, CancellationToken ct = default);
    Task AttachScopeToRoleAsync(long roleId, long scopeId, CancellationToken ct = default);
    Task DetachScopeFromRoleAsync(long roleId, long scopeId, CancellationToken ct = default);
}

public sealed partial class IdentityClient
{
    private const string RolesBase = "/api/v1/identity/roles";

    public async Task<PagedResult<RoleResponse>> SearchRolesAsync(
        string? query = null, string? audience = null, long? applicationId = null,
        int offset = 0, int count = 25, CancellationToken ct = default)
    {
        var url = $"{RolesBase}?offset={offset}&count={count}";
        if (!string.IsNullOrEmpty(query)) url += $"&query={Uri.EscapeDataString(query)}";
        if (!string.IsNullOrEmpty(audience)) url += $"&audience={Uri.EscapeDataString(audience)}";
        if (applicationId.HasValue) url += $"&applicationId={applicationId.Value}";
        using var resp = await _http.GetAsync(url, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<PagedResult<RoleResponse>>(ct).ConfigureAwait(false);
    }

    public async Task<RoleResponse> GetRoleAsync(long id, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{RolesBase}/{id}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<RoleResponse>(ct).ConfigureAwait(false);
    }

    public async Task<RoleResponse> CreateRoleAsync(CreateRoleRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync(RolesBase, request, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<RoleResponse>(ct).ConfigureAwait(false);
    }

    public async Task UpdateRoleAsync(long id, UpdateRoleRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PutAsJsonAsync($"{RolesBase}/{id}", request, _json, ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
    }

    public async Task DeleteRoleAsync(long id, CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{RolesBase}/{id}", ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<RoleAssignmentResponse>> ListRoleAssigneesAsync(long roleId, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{RolesBase}/{roleId}/assignees", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<List<RoleAssignmentResponse>>(ct).ConfigureAwait(false);
    }

    public async Task AssignUserToRoleAsync(long roleId, long userId, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{RolesBase}/{roleId}/users",
            new Dictionary<string, object?> { ["userId"] = userId }, _json, ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
    }

    public async Task UnassignUserFromRoleAsync(long roleId, long userId, CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{RolesBase}/{roleId}/users/{userId}", ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
    }

    public async Task AssignGroupToRoleAsync(long roleId, long groupId, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{RolesBase}/{roleId}/groups",
            new Dictionary<string, object?> { ["groupId"] = groupId }, _json, ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
    }

    public async Task UnassignGroupFromRoleAsync(long roleId, long groupId, CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{RolesBase}/{roleId}/groups/{groupId}", ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<RoleScopeResponse>> ListRoleScopesAsync(long roleId, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{RolesBase}/{roleId}/scopes", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<List<RoleScopeResponse>>(ct).ConfigureAwait(false);
    }

    public async Task AttachScopeToRoleAsync(long roleId, long scopeId, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{RolesBase}/{roleId}/scopes",
            new Dictionary<string, object?> { ["scopeId"] = scopeId }, _json, ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
    }

    public async Task DetachScopeFromRoleAsync(long roleId, long scopeId, CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{RolesBase}/{roleId}/scopes/{scopeId}", ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
    }
}
