using System.Text.Json;
using redb.Identity.Client.Internal;
using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Groups;

namespace redb.Identity.Client;

public partial interface IIdentityClient
{
    // ── Group CRUD ──
    Task<IReadOnlyList<GroupResponse>> ListRootGroupsAsync(int offset = 0, int count = 25, CancellationToken ct = default);
    Task<PagedResult<GroupResponse>> SearchGroupsAsync(
        string? query = null, string? groupType = null,
        int offset = 0, int count = 25, CancellationToken ct = default);
    Task<GroupResponse> GetGroupAsync(long id, CancellationToken ct = default);
    Task<GroupResponse> CreateGroupAsync(CreateGroupRequest request, CancellationToken ct = default);
    Task<GroupResponse> CreateChildGroupAsync(long parentId, CreateGroupRequest request, CancellationToken ct = default);
    Task UpdateGroupAsync(long id, UpdateGroupRequest request, CancellationToken ct = default);
    Task DeleteGroupAsync(long id, CancellationToken ct = default);
    Task MoveGroupAsync(long id, MoveGroupRequest request, CancellationToken ct = default);

    // ── Tree operations ──
    Task<JsonElement> GetGroupTreeAsync(long id, CancellationToken ct = default);
    Task<IReadOnlyList<GroupResponse>> GetGroupPathAsync(long id, CancellationToken ct = default);
    Task<IReadOnlyList<GroupResponse>> GetGroupChildrenAsync(long id, CancellationToken ct = default);

    // ── Membership ──
    Task<IReadOnlyList<MemberResponse>> ListGroupMembersAsync(long id, CancellationToken ct = default);
    Task AddGroupMemberAsync(long id, AddMemberRequest request, CancellationToken ct = default);
    Task UpdateGroupMemberAsync(long id, long userId, UpdateMemberRequest request, CancellationToken ct = default);
    Task RemoveGroupMemberAsync(long id, long userId, CancellationToken ct = default);
    Task<JsonElement> GetUserGroupsAsync(long userId, CancellationToken ct = default);
    Task<bool> IsGroupMemberAsync(long id, long userId, CancellationToken ct = default);
}

public sealed partial class IdentityClient
{
    private const string GroupsBase = "/api/v1/identity/groups";

    public async Task<IReadOnlyList<GroupResponse>> ListRootGroupsAsync(int offset = 0, int count = 25, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{GroupsBase}?offset={offset}&count={count}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<List<GroupResponse>>(ct).ConfigureAwait(false);
    }

    public async Task<PagedResult<GroupResponse>> SearchGroupsAsync(
        string? query = null, string? groupType = null,
        int offset = 0, int count = 25, CancellationToken ct = default)
    {
        var url = $"{GroupsBase}/search?offset={offset}&count={count}";
        if (!string.IsNullOrEmpty(query)) url += $"&query={Uri.EscapeDataString(query)}";
        if (!string.IsNullOrEmpty(groupType)) url += $"&groupType={Uri.EscapeDataString(groupType)}";
        using var resp = await _http.GetAsync(url, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<PagedResult<GroupResponse>>(ct).ConfigureAwait(false);
    }

    public async Task<GroupResponse> GetGroupAsync(long id, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{GroupsBase}/{id}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<GroupResponse>(ct).ConfigureAwait(false);
    }

    public async Task<GroupResponse> CreateGroupAsync(CreateGroupRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync(GroupsBase, request, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<GroupResponse>(ct).ConfigureAwait(false);
    }

    public async Task<GroupResponse> CreateChildGroupAsync(long parentId, CreateGroupRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{GroupsBase}/{parentId}/children", request, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<GroupResponse>(ct).ConfigureAwait(false);
    }

    public async Task UpdateGroupAsync(long id, UpdateGroupRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PutAsJsonAsync($"{GroupsBase}/{id}", request, _json, ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
    }

    public async Task DeleteGroupAsync(long id, CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{GroupsBase}/{id}", ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
    }

    public async Task MoveGroupAsync(long id, MoveGroupRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{GroupsBase}/{id}/move", request, _json, ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
    }

    // ── Tree operations ──

    public async Task<JsonElement> GetGroupTreeAsync(long id, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{GroupsBase}/{id}/tree", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<GroupResponse>> GetGroupPathAsync(long id, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{GroupsBase}/{id}/path", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<List<GroupResponse>>(ct).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<GroupResponse>> GetGroupChildrenAsync(long id, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{GroupsBase}/{id}/children", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<List<GroupResponse>>(ct).ConfigureAwait(false);
    }

    // ── Membership ──

    public async Task<IReadOnlyList<MemberResponse>> ListGroupMembersAsync(long id, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{GroupsBase}/{id}/members", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<List<MemberResponse>>(ct).ConfigureAwait(false);
    }

    public async Task AddGroupMemberAsync(long id, AddMemberRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{GroupsBase}/{id}/members", request, _json, ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
    }

    public async Task UpdateGroupMemberAsync(long id, long userId, UpdateMemberRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PutAsJsonAsync($"{GroupsBase}/{id}/members/{userId}", request, _json, ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
    }

    public async Task RemoveGroupMemberAsync(long id, long userId, CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{GroupsBase}/{id}/members/{userId}", ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> GetUserGroupsAsync(long userId, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{GroupsBase}/users/{userId}/groups", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<bool> IsGroupMemberAsync(long id, long userId, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{GroupsBase}/{id}/members/{userId}/check", ct).ConfigureAwait(false);
        var doc = await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
        return doc.TryGetProperty("isMember", out var prop) && prop.ValueKind == JsonValueKind.True;
    }
}
