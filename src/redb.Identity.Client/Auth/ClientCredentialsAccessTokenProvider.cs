using System.Text.Json;
using Microsoft.Extensions.Options;

namespace redb.Identity.Client.Auth;

/// <summary>
/// <see cref="IAccessTokenProvider"/> implementation using OAuth2 client_credentials grant.
/// Caches the access token until ~1 minute before expiry. Use for CLI / server-to-server
/// scenarios. Web should provide its own per-request HttpContext-based provider.
/// </summary>
public sealed class ClientCredentialsAccessTokenProvider : IAccessTokenProvider, IDisposable
{
    private readonly HttpClient _http;
    private readonly IdentityClientOptions _opts;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private string? _cachedToken;
    private DateTimeOffset _expiresAt = DateTimeOffset.MinValue;

    public ClientCredentialsAccessTokenProvider(HttpClient http, IOptions<IdentityClientOptions> opts)
    {
        _http = http;
        _opts = opts.Value;
        _http.BaseAddress = _opts.BaseUrl;
    }

    public async Task<string?> GetAccessTokenAsync(CancellationToken ct = default)
    {
        if (_cachedToken is not null && DateTimeOffset.UtcNow < _expiresAt - TimeSpan.FromMinutes(1))
            return _cachedToken;

        await _lock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            // Double-check after acquiring lock
            if (_cachedToken is not null && DateTimeOffset.UtcNow < _expiresAt - TimeSpan.FromMinutes(1))
                return _cachedToken;

            if (string.IsNullOrEmpty(_opts.ClientId) || string.IsNullOrEmpty(_opts.ClientSecret))
                throw new InvalidOperationException(
                    "ClientCredentialsAccessTokenProvider requires ClientId+ClientSecret in IdentityClientOptions.");

            var form = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "client_credentials"),
                new KeyValuePair<string, string>("client_id", _opts.ClientId),
                new KeyValuePair<string, string>("client_secret", _opts.ClientSecret),
                new KeyValuePair<string, string>("scope", string.Join(' ', _opts.Scopes)),
            });

            using var resp = await _http.PostAsync("/connect/token", form, ct).ConfigureAwait(false);
            resp.EnsureSuccessStatusCode();
            var json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            _cachedToken = doc.RootElement.GetProperty("access_token").GetString()!;
            var expiresIn = doc.RootElement.TryGetProperty("expires_in", out var ei)
                ? ei.GetInt32() : 3600;
            _expiresAt = DateTimeOffset.UtcNow.AddSeconds(expiresIn);
            return _cachedToken;
        }
        finally
        {
            _lock.Release();
        }
    }

    public void Dispose() => _lock.Dispose();
}
