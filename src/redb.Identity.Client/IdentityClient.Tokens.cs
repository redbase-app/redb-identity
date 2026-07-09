using System.Text.Json;

namespace redb.Identity.Client;

public partial interface IIdentityClient
{
    /// <summary>List tokens, optionally filtered by subject (admin).</summary>
    Task<JsonElement> ListTokensAsync(string? subject = null, int offset = 0, int count = 20, CancellationToken ct = default);

    /// <summary>Revoke a single token by id (admin).</summary>
    Task<JsonElement> RevokeTokenAdminAsync(string tokenId, CancellationToken ct = default);

    /// <summary>Revoke all tokens for a subject (admin).</summary>
    Task<JsonElement> RevokeTokensBySubjectAsync(IDictionary<string, object> request, CancellationToken ct = default);

    /// <summary>Trigger pruning of expired tokens (admin, may be slow).</summary>
    Task<JsonElement> PruneTokensAsync(CancellationToken ct = default);
}

public sealed partial class IdentityClient
{
    private const string TokensAdminBase = "/api/v1/identity/tokens";

    public async Task<JsonElement> ListTokensAsync(string? subject = null, int offset = 0, int count = 20, CancellationToken ct = default)
    {
        var url = $"{TokensAdminBase}?offset={offset}&count={count}"
            + (subject is null ? "" : $"&subject={Uri.EscapeDataString(subject)}");
        using var resp = await _http.GetAsync(url, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> RevokeTokenAdminAsync(string tokenId, CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{TokensAdminBase}/{Uri.EscapeDataString(tokenId)}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> RevokeTokensBySubjectAsync(IDictionary<string, object> request, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{TokensAdminBase}/revoke-by-subject", request, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> PruneTokensAsync(CancellationToken ct = default)
    {
        using var resp = await _http.PostAsync($"{TokensAdminBase}/prune", content: null, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }
}
