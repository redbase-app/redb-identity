using System.Text.Json;

namespace redb.Identity.Client;

public partial interface IIdentityClient
{
    /// <summary>OIDC discovery document (<c>/.well-known/openid-configuration</c>).</summary>
    Task<JsonElement> GetDiscoveryDocumentAsync(CancellationToken ct = default);

    /// <summary>JWKS endpoint. URL is read from <c>discovery.jwks_uri</c>
    /// to stay consistent with the server's actual route (which omits
    /// <c>.json</c> on this implementation).</summary>
    Task<JsonElement> GetJwksAsync(CancellationToken ct = default);
}

public sealed partial class IdentityClient
{
    public async Task<JsonElement> GetDiscoveryDocumentAsync(CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync("/.well-known/openid-configuration", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> GetJwksAsync(CancellationToken ct = default)
    {
        // Server exposes /.well-known/jwks (no .json suffix). Hitting the .json
        // variant returns 404 which the Settings page UX was surfacing as a
        // broken probe — keep this aligned with the discovery jwks_uri.
        using var resp = await _http.GetAsync("/.well-known/jwks", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }
}
