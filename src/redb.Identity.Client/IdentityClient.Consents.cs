using System.Text.Json;

namespace redb.Identity.Client;

public partial interface IIdentityClient
{
    /// <summary>List consent grants for a user (admin).</summary>
    Task<JsonElement> ListUserConsentsAsync(long userId, CancellationToken ct = default);

    /// <summary>Revoke a single consent grant (admin).</summary>
    Task<JsonElement> RevokeUserConsentAsync(long userId, long applicationId, CancellationToken ct = default);

    /// <summary>Revoke all consent grants of a user (admin).</summary>
    Task<JsonElement> RevokeAllUserConsentsAsync(long userId, CancellationToken ct = default);
}

public sealed partial class IdentityClient
{
    private const string ConsentsAdminBase = "/api/v1/identity/consents";

    public async Task<JsonElement> ListUserConsentsAsync(long userId, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{ConsentsAdminBase}?userId={userId}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> RevokeUserConsentAsync(long userId, long applicationId, CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{ConsentsAdminBase}?userId={userId}&applicationId={applicationId}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> RevokeAllUserConsentsAsync(long userId, CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{ConsentsAdminBase}/all?userId={userId}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }
}
