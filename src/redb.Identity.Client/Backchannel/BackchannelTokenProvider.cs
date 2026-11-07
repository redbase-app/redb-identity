using System.Text.Json;
using Microsoft.Extensions.Options;

namespace redb.Identity.Client.Backchannel;

/// <summary>
/// Caches a <c>client_credentials</c> access token for the backchannel client.
/// Isolated from the global <see cref="Auth.IAccessTokenProvider"/> registration so a
/// Web BFF can keep its user-context provider while this one serves machine-context
/// requests.
/// </summary>
internal sealed class BackchannelTokenProvider : IDisposable
{
    private readonly HttpClient _http;
    private readonly IOptions<BackchannelIdentityClientOptions> _opts;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private string? _cachedToken;
    private DateTimeOffset _expiresAt = DateTimeOffset.MinValue;

    public BackchannelTokenProvider(HttpClient http, IOptions<BackchannelIdentityClientOptions> opts)
    {
        _http = http;
        _opts = opts;
        _http.BaseAddress = opts.Value.BaseUrl;
    }

    public async Task<string?> GetAccessTokenAsync(CancellationToken ct = default)
    {
        if (_cachedToken is not null && DateTimeOffset.UtcNow < _expiresAt - TimeSpan.FromMinutes(1))
            return _cachedToken;

        await _lock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_cachedToken is not null && DateTimeOffset.UtcNow < _expiresAt - TimeSpan.FromMinutes(1))
                return _cachedToken;

            var opts = _opts.Value;
            if (string.IsNullOrEmpty(opts.ClientId) || string.IsNullOrEmpty(opts.ClientSecret))
                throw new InvalidOperationException(
                    "BackchannelTokenProvider requires BackchannelIdentityClientOptions.ClientId and ClientSecret.");

            var form = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "client_credentials"),
                new KeyValuePair<string, string>("client_id", opts.ClientId),
                new KeyValuePair<string, string>("client_secret", opts.ClientSecret),
                new KeyValuePair<string, string>("scope", string.Join(' ', opts.Scopes)),
            });

            using var resp = await _http.PostAsync("/connect/token", form, ct).ConfigureAwait(false);
            resp.EnsureSuccessStatusCode();
            var json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            _cachedToken = doc.RootElement.GetProperty("access_token").GetString()!;
            var expiresIn = doc.RootElement.TryGetProperty("expires_in", out var ei) ? ei.GetInt32() : 3600;
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
