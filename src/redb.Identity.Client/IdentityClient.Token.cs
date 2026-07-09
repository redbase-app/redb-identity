using System.Net.Http.Headers;
using System.Text.Json;
using redb.Identity.Contracts.Tokens;

namespace redb.Identity.Client;

public partial interface IIdentityClient
{
    /// <summary>OAuth/OIDC token endpoint (RFC 6749 §3.2). Sends form-urlencoded body.</summary>
    Task<TokenResponse> RequestTokenAsync(TokenRequest request, CancellationToken ct = default);

    /// <summary>Token introspection (RFC 7662). Client-authenticated.</summary>
    Task<IntrospectionResponse> IntrospectTokenAsync(string token, string? tokenTypeHint = null, string? clientId = null, string? clientSecret = null, CancellationToken ct = default);

    /// <summary>Token revocation (RFC 7009). Client-authenticated.</summary>
    Task<JsonElement> RevokeOAuthTokenAsync(string token, string? tokenTypeHint = null, string? clientId = null, string? clientSecret = null, CancellationToken ct = default);

    /// <summary>OIDC UserInfo endpoint. Requires Bearer access token with <c>openid</c> scope.</summary>
    Task<JsonElement> GetUserInfoAsync(CancellationToken ct = default);
}

public sealed partial class IdentityClient
{
    private const string ConnectBase = "/connect";

    public async Task<TokenResponse> RequestTokenAsync(TokenRequest request, CancellationToken ct = default)
    {
        var form = ToFormFields(request);
        using var resp = await _http.PostAsync($"{ConnectBase}/token", new FormUrlEncodedContent(form), ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<TokenResponse>(ct).ConfigureAwait(false);
    }

    public async Task<IntrospectionResponse> IntrospectTokenAsync(string token, string? tokenTypeHint = null, string? clientId = null, string? clientSecret = null, CancellationToken ct = default)
    {
        var form = new List<KeyValuePair<string, string>> { new("token", token) };
        if (tokenTypeHint is not null) form.Add(new("token_type_hint", tokenTypeHint));
        if (clientId is not null) form.Add(new("client_id", clientId));
        if (clientSecret is not null) form.Add(new("client_secret", clientSecret));

        using var resp = await _http.PostAsync($"{ConnectBase}/introspect", new FormUrlEncodedContent(form), ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<IntrospectionResponse>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> RevokeOAuthTokenAsync(string token, string? tokenTypeHint = null, string? clientId = null, string? clientSecret = null, CancellationToken ct = default)
    {
        var form = new List<KeyValuePair<string, string>> { new("token", token) };
        if (tokenTypeHint is not null) form.Add(new("token_type_hint", tokenTypeHint));
        if (clientId is not null) form.Add(new("client_id", clientId));
        if (clientSecret is not null) form.Add(new("client_secret", clientSecret));

        using var resp = await _http.PostAsync($"{ConnectBase}/revocation", new FormUrlEncodedContent(form), ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> GetUserInfoAsync(CancellationToken ct = default)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, $"{ConnectBase}/userinfo");
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    private static List<KeyValuePair<string, string>> ToFormFields(TokenRequest req)
    {
        var fields = new List<KeyValuePair<string, string>>
        {
            new("grant_type", req.GrantType),
        };
        if (req.ClientId is not null) fields.Add(new("client_id", req.ClientId));
        if (req.ClientSecret is not null) fields.Add(new("client_secret", req.ClientSecret));
        if (req.Scope is not null) fields.Add(new("scope", req.Scope));
        if (req.Code is not null) fields.Add(new("code", req.Code));
        if (req.RedirectUri is not null) fields.Add(new("redirect_uri", req.RedirectUri));
        if (req.RefreshToken is not null) fields.Add(new("refresh_token", req.RefreshToken));
        if (req.CodeVerifier is not null) fields.Add(new("code_verifier", req.CodeVerifier));
        if (req.Username is not null) fields.Add(new("username", req.Username));
        if (req.Password is not null) fields.Add(new("password", req.Password));
        return fields;
    }
}
