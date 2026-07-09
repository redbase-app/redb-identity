using System.Text.Json;

namespace redb.Identity.Client;

public partial interface IIdentityClient
{
    /// <summary>
    /// N7-3 — start an admin impersonation overlay (audit beacon).
    /// Returns the resolved target user info. Requires <c>identity:impersonate</c>
    /// or master <c>identity:manage</c> scope on the caller's bearer token.
    /// </summary>
    Task<JsonElement> StartImpersonationAsync(long targetUserId, string? reason = null, CancellationToken ct = default);

    /// <summary>
    /// N7-3 — stop an admin impersonation overlay (audit beacon). Same scope requirement.
    /// </summary>
    Task<JsonElement> StopImpersonationAsync(long targetUserId, CancellationToken ct = default);
}

public sealed partial class IdentityClient
{
    private const string ImpersonationBase = "/api/v1/identity/admin/impersonate";

    /// <inheritdoc cref="IIdentityClient.StartImpersonationAsync"/>
    public async Task<JsonElement> StartImpersonationAsync(long targetUserId, string? reason = null, CancellationToken ct = default)
    {
        var body = new { reason };
        using var resp = await _http.PostAsJsonAsync($"{ImpersonationBase}/start/{targetUserId}", body, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    /// <inheritdoc cref="IIdentityClient.StopImpersonationAsync"/>
    public async Task<JsonElement> StopImpersonationAsync(long targetUserId, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{ImpersonationBase}/stop/{targetUserId}", new { }, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }
}
