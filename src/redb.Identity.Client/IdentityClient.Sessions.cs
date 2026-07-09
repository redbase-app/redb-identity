using System.Text.Json;

namespace redb.Identity.Client;

public partial interface IIdentityClient
{
    /// <summary>List active sessions for a user (admin).</summary>
    Task<JsonElement> ListSessionsAsync(long userId, CancellationToken ct = default);
    Task<JsonElement> ListAllSessionsAsync(int offset = 0, int count = 25, CancellationToken ct = default);

    /// <summary>Revoke a single session by id (admin).</summary>
    Task<JsonElement> RevokeSessionAsync(long sessionId, CancellationToken ct = default);

    /// <summary>Revoke all sessions of a user (admin).</summary>
    Task<JsonElement> RevokeAllUserSessionsAsync(long userId, CancellationToken ct = default);

    /// <summary>Force-logout a user (revokes sessions + tokens, admin).</summary>
    Task<JsonElement> ForceLogoutUserAsync(long userId, CancellationToken ct = default);
}

public sealed partial class IdentityClient
{
    private const string SessionsBase = "/api/v1/identity/sessions";

    public async Task<JsonElement> ListSessionsAsync(long userId, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{SessionsBase}?userId={userId}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Admin-wide paginated browse of active sessions across all users —
    /// powers the /admin/sessions default view. <see cref="ListSessionsAsync"/>
    /// stays the targeted per-user path.
    /// </summary>
    public async Task<JsonElement> ListAllSessionsAsync(int offset = 0, int count = 25, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{SessionsBase}?offset={offset}&count={count}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> RevokeSessionAsync(long sessionId, CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{SessionsBase}?sessionId={sessionId}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> RevokeAllUserSessionsAsync(long userId, CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{SessionsBase}/all?userId={userId}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> ForceLogoutUserAsync(long userId, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsync($"{SessionsBase}/logout?userId={userId}", content: null, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }
}
