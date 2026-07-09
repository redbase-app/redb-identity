using redb.Identity.Contracts.Applications;
using redb.Identity.Contracts.Common;

namespace redb.Identity.Client;

public partial interface IIdentityClient
{
    Task<PagedResult<ApplicationResponse>> ListApplicationsAsync(int offset = 0, int count = 25, CancellationToken ct = default);
    Task<ApplicationResponse> GetApplicationAsync(string id, CancellationToken ct = default);
    Task<ApplicationResponse> CreateApplicationAsync(CreateApplicationRequest request, CancellationToken ct = default);
    Task<ApplicationResponse> UpdateApplicationAsync(string id, UpdateApplicationRequest request, CancellationToken ct = default);
    Task DeleteApplicationAsync(string id, CancellationToken ct = default);

    /// <summary>
    /// Rotates the <c>client_secret</c> of a confidential application. The returned
    /// <see cref="ApplicationResponse.NewSecret"/> field carries the freshly generated
    /// plaintext secret — copy it immediately, subsequent calls will not expose it again
    /// (server stores only the BCrypt hash). The previous secret stops working at the
    /// token endpoint as soon as this call succeeds.
    /// </summary>
    Task<ApplicationResponse> RotateApplicationSecretAsync(string id, CancellationToken ct = default);
}

public sealed partial class IdentityClient
{
    private const string ApplicationsBase = "/api/v1/identity/applications";

    public async Task<PagedResult<ApplicationResponse>> ListApplicationsAsync(int offset = 0, int count = 25, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{ApplicationsBase}?offset={offset}&count={count}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<PagedResult<ApplicationResponse>>(ct).ConfigureAwait(false);
    }

    public async Task<ApplicationResponse> GetApplicationAsync(string id, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{ApplicationsBase}/{Uri.EscapeDataString(id)}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<ApplicationResponse>(ct).ConfigureAwait(false);
    }

    public async Task<ApplicationResponse> CreateApplicationAsync(CreateApplicationRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync(ApplicationsBase, request, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<ApplicationResponse>(ct).ConfigureAwait(false);
    }

    public async Task<ApplicationResponse> UpdateApplicationAsync(string id, UpdateApplicationRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PutAsJsonAsync($"{ApplicationsBase}/{Uri.EscapeDataString(id)}", request, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<ApplicationResponse>(ct).ConfigureAwait(false);
    }

    public async Task DeleteApplicationAsync(string id, CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{ApplicationsBase}/{Uri.EscapeDataString(id)}", ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
    }

    public async Task<ApplicationResponse> RotateApplicationSecretAsync(string id, CancellationToken ct = default)
    {
        // Empty content body — server identifies the target purely from the route id.
        using var resp = await _http.PostAsync(
            $"{ApplicationsBase}/{Uri.EscapeDataString(id)}/rotate-secret",
            content: null,
            ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<ApplicationResponse>(ct).ConfigureAwait(false);
    }
}
