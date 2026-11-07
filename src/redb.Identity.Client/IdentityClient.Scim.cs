using System.Text.Json;
using redb.Identity.Contracts.Scim;

namespace redb.Identity.Client;

public partial interface IIdentityClient
{
    // ── Discovery ──
    /// <summary>SCIM 2.0 ServiceProviderConfig (RFC 7643 §5).</summary>
    Task<ScimServiceProviderConfig> GetScimServiceProviderConfigAsync(CancellationToken ct = default);
    /// <summary>SCIM 2.0 ResourceTypes list.</summary>
    Task<JsonElement> GetScimResourceTypesAsync(CancellationToken ct = default);
    /// <summary>SCIM 2.0 Schemas list.</summary>
    Task<JsonElement> GetScimSchemasAsync(CancellationToken ct = default);

    // ── Users ──
    /// <summary>List SCIM users (startIndex/count + optional filter — SCIM 2.0 spec).</summary>
    Task<ScimListResponse<ScimUser>> ListScimUsersAsync(int startIndex = 1, int count = 25, string? filter = null, string? sortBy = null, string? sortOrder = null, CancellationToken ct = default);
    Task<ScimUser> GetScimUserAsync(string id, CancellationToken ct = default);
    Task<ScimUser> CreateScimUserAsync(ScimUser user, CancellationToken ct = default);
    Task<ScimUser> ReplaceScimUserAsync(string id, ScimUser user, CancellationToken ct = default);
    Task<ScimUser> PatchScimUserAsync(string id, ScimPatchRequest patch, CancellationToken ct = default);
    Task DeleteScimUserAsync(string id, CancellationToken ct = default);

    // ── Groups ──
    Task<ScimListResponse<ScimGroup>> ListScimGroupsAsync(int startIndex = 1, int count = 25, string? filter = null, string? sortBy = null, string? sortOrder = null, CancellationToken ct = default);
    Task<ScimGroup> GetScimGroupAsync(string id, CancellationToken ct = default);
    Task<ScimGroup> CreateScimGroupAsync(ScimGroup group, CancellationToken ct = default);
    Task<ScimGroup> ReplaceScimGroupAsync(string id, ScimGroup group, CancellationToken ct = default);
    Task<ScimGroup> PatchScimGroupAsync(string id, ScimPatchRequest patch, CancellationToken ct = default);
    Task DeleteScimGroupAsync(string id, CancellationToken ct = default);

    // ── Bulk ──
    /// <summary>SCIM 2.0 Bulk operations (RFC 7644 §3.7).</summary>
    Task<ScimBulkResponse> ExecuteScimBulkAsync(ScimBulkRequest request, CancellationToken ct = default);
}

public sealed partial class IdentityClient
{
    private const string ScimBase = "/scim/v2";

    // ── Discovery ──
    public async Task<ScimServiceProviderConfig> GetScimServiceProviderConfigAsync(CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{ScimBase}/ServiceProviderConfig", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<ScimServiceProviderConfig>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> GetScimResourceTypesAsync(CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{ScimBase}/ResourceTypes", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> GetScimSchemasAsync(CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{ScimBase}/Schemas", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    // ── Users ──
    public async Task<ScimListResponse<ScimUser>> ListScimUsersAsync(int startIndex = 1, int count = 25, string? filter = null, string? sortBy = null, string? sortOrder = null, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync(BuildScimListUrl($"{ScimBase}/Users", startIndex, count, filter, sortBy, sortOrder), ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<ScimListResponse<ScimUser>>(ct).ConfigureAwait(false);
    }

    public async Task<ScimUser> GetScimUserAsync(string id, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{ScimBase}/Users/{Uri.EscapeDataString(id)}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<ScimUser>(ct).ConfigureAwait(false);
    }

    public async Task<ScimUser> CreateScimUserAsync(ScimUser user, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{ScimBase}/Users", user, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<ScimUser>(ct).ConfigureAwait(false);
    }

    public async Task<ScimUser> ReplaceScimUserAsync(string id, ScimUser user, CancellationToken ct = default)
    {
        using var resp = await _http.PutAsJsonAsync($"{ScimBase}/Users/{Uri.EscapeDataString(id)}", user, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<ScimUser>(ct).ConfigureAwait(false);
    }

    public async Task<ScimUser> PatchScimUserAsync(string id, ScimPatchRequest patch, CancellationToken ct = default)
    {
        var url = $"{ScimBase}/Users/{Uri.EscapeDataString(id)}";
        using var req = new HttpRequestMessage(HttpMethod.Patch, url) { Content = JsonContent.Create(patch, options: _json) };
        using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<ScimUser>(ct).ConfigureAwait(false);
    }

    public async Task DeleteScimUserAsync(string id, CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{ScimBase}/Users/{Uri.EscapeDataString(id)}", ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
    }

    // ── Groups ──
    public async Task<ScimListResponse<ScimGroup>> ListScimGroupsAsync(int startIndex = 1, int count = 25, string? filter = null, string? sortBy = null, string? sortOrder = null, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync(BuildScimListUrl($"{ScimBase}/Groups", startIndex, count, filter, sortBy, sortOrder), ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<ScimListResponse<ScimGroup>>(ct).ConfigureAwait(false);
    }

    public async Task<ScimGroup> GetScimGroupAsync(string id, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{ScimBase}/Groups/{Uri.EscapeDataString(id)}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<ScimGroup>(ct).ConfigureAwait(false);
    }

    public async Task<ScimGroup> CreateScimGroupAsync(ScimGroup group, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{ScimBase}/Groups", group, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<ScimGroup>(ct).ConfigureAwait(false);
    }

    public async Task<ScimGroup> ReplaceScimGroupAsync(string id, ScimGroup group, CancellationToken ct = default)
    {
        using var resp = await _http.PutAsJsonAsync($"{ScimBase}/Groups/{Uri.EscapeDataString(id)}", group, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<ScimGroup>(ct).ConfigureAwait(false);
    }

    public async Task<ScimGroup> PatchScimGroupAsync(string id, ScimPatchRequest patch, CancellationToken ct = default)
    {
        var url = $"{ScimBase}/Groups/{Uri.EscapeDataString(id)}";
        using var req = new HttpRequestMessage(HttpMethod.Patch, url) { Content = JsonContent.Create(patch, options: _json) };
        using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<ScimGroup>(ct).ConfigureAwait(false);
    }

    public async Task DeleteScimGroupAsync(string id, CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{ScimBase}/Groups/{Uri.EscapeDataString(id)}", ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
    }

    // ── Bulk ──
    public async Task<ScimBulkResponse> ExecuteScimBulkAsync(ScimBulkRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{ScimBase}/Bulk", request, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<ScimBulkResponse>(ct).ConfigureAwait(false);
    }

    private static string BuildScimListUrl(string basePath, int startIndex, int count, string? filter, string? sortBy, string? sortOrder)
    {
        var parts = new List<string> { $"startIndex={startIndex}", $"count={count}" };
        if (!string.IsNullOrEmpty(filter)) parts.Add($"filter={Uri.EscapeDataString(filter)}");
        if (!string.IsNullOrEmpty(sortBy)) parts.Add($"sortBy={Uri.EscapeDataString(sortBy)}");
        if (!string.IsNullOrEmpty(sortOrder)) parts.Add($"sortOrder={Uri.EscapeDataString(sortOrder)}");
        return $"{basePath}?{string.Join("&", parts)}";
    }
}
