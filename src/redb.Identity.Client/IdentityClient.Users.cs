using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Users;

namespace redb.Identity.Client;

public partial interface IIdentityClient
{
    Task<PagedResult<UserResponse>> ListUsersAsync(int offset = 0, int count = 25, CancellationToken ct = default);
    Task<UserResponse> GetUserAsync(string idOrLogin, CancellationToken ct = default);
    Task<UserResponse> CreateUserAsync(CreateUserRequest request, CancellationToken ct = default);
    Task<UserResponse> UpdateUserAsync(long id, UpdateUserRequest request, CancellationToken ct = default);
    Task DeleteUserAsync(string idOrLogin, CancellationToken ct = default);
    Task ChangeUserPasswordAsync(long id, ChangePasswordRequest request, CancellationToken ct = default);

    /// <summary>
    /// Admin-side password reset for the given user. Bypasses the OldPassword
    /// challenge that the regular change-password flow requires — operator's
    /// <c>identity:users.manage</c> / <c>identity:manage</c> scope IS the
    /// authorization. Revokes every existing session as a side effect.
    /// </summary>
    Task AdminResetUserPasswordAsync(long id, AdminResetPasswordRequest request, CancellationToken ct = default);

    Task<IReadOnlyList<UserResponse>> SearchUsersAsync(string query, CancellationToken ct = default);

    /// <summary>
    /// Paginated user search. Returns total match count + the requested page.
    /// Use this over the legacy non-paginated overload when the tenant may
    /// have more than the server-side per-page cap (200) matching the query.
    /// </summary>
    Task<PagedResult<UserResponse>> SearchUsersPagedAsync(string query, int offset = 0, int count = 25, CancellationToken ct = default);
}

public sealed partial class IdentityClient
{
    private const string UsersBase = "/api/v1/identity/users";

    public async Task<PagedResult<UserResponse>> ListUsersAsync(int offset = 0, int count = 25, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{UsersBase}?offset={offset}&count={count}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<PagedResult<UserResponse>>(ct).ConfigureAwait(false);
    }

    public async Task<UserResponse> GetUserAsync(string idOrLogin, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{UsersBase}/{Uri.EscapeDataString(idOrLogin)}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<UserResponse>(ct).ConfigureAwait(false);
    }

    public async Task<UserResponse> CreateUserAsync(CreateUserRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync(UsersBase, request, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<UserResponse>(ct).ConfigureAwait(false);
    }

    public async Task<UserResponse> UpdateUserAsync(long id, UpdateUserRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PutAsJsonAsync($"{UsersBase}/{id}", request, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<UserResponse>(ct).ConfigureAwait(false);
    }

    public async Task DeleteUserAsync(string idOrLogin, CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{UsersBase}/{Uri.EscapeDataString(idOrLogin)}", ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
    }

    public async Task ChangeUserPasswordAsync(long id, ChangePasswordRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{UsersBase}/{id}/change-password", request, _json, ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
    }

    public async Task AdminResetUserPasswordAsync(long id, AdminResetPasswordRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{UsersBase}/{id}/admin-reset-password", request, _json, ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<UserResponse>> SearchUsersAsync(string query, CancellationToken ct = default)
    {
        var page = await SearchUsersPagedAsync(query, 0, 200, ct).ConfigureAwait(false);
        return page.Items;
    }

    public async Task<PagedResult<UserResponse>> SearchUsersPagedAsync(string query, int offset = 0, int count = 25, CancellationToken ct = default)
    {
        var url = $"{UsersBase}/search?query={Uri.EscapeDataString(query)}&offset={offset}&count={count}";
        using var resp = await _http.GetAsync(url, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<PagedResult<UserResponse>>(ct).ConfigureAwait(false);
    }
}
