using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using redb.Identity.Core.Configuration;
using redb.Identity.Contracts.Configuration;

namespace redb.Identity.Core.Services;

/// <summary>
/// H8 (DoD §4 gap (a) "GitHub-style"): GitHub OAuth2 federated auth provider.
/// Unlike <see cref="OidcFederatedAuthProvider"/>, GitHub is OAuth2 only — no
/// <c>id_token</c> and no OIDC discovery, so we exchange the auth code for an
/// <c>access_token</c> and then call <c>/user</c> + <c>/user/emails</c> to build
/// the <see cref="ExternalAuthResult"/>.
/// <para>
/// PKCE is supported (GitHub added S256 PKCE in 2022 and ignores <c>code_verifier</c>
/// silently for old apps), nonce is not — GitHub has no id_token to bind it to.
/// </para>
/// <para>
/// Required scope to obtain a primary verified email when the profile email is
/// private: <c>user:email</c> (we add it implicitly if the caller forgot).
/// </para>
/// </summary>
public sealed class GitHubFederatedAuthProvider : IFederatedAuthProvider
{
    // Defaults — public github.com. Override via FederationProviderConfig.Endpoints to
    // support GitHub Enterprise, Gitea, or a self-hosted mock for testing.
    private const string DefaultAuthorizeEndpoint = "https://github.com/login/oauth/authorize";
    private const string DefaultTokenEndpoint = "https://github.com/login/oauth/access_token";
    private const string DefaultUserEndpoint = "https://api.github.com/user";
    private const string DefaultEmailsEndpoint = "https://api.github.com/user/emails";

    private readonly FederationProviderConfig _config;
    private readonly IHttpClientFactory _httpClientFactory;

    private string AuthorizeEndpoint =>
        _config.Endpoints?.AuthorizeEndpoint ?? DefaultAuthorizeEndpoint;
    private string TokenEndpoint =>
        _config.Endpoints?.TokenEndpoint ?? DefaultTokenEndpoint;
    private string UserEndpoint =>
        _config.Endpoints?.UserEndpoint ?? DefaultUserEndpoint;
    private string EmailsEndpoint =>
        _config.Endpoints?.EmailsEndpoint ?? DefaultEmailsEndpoint;

    public GitHubFederatedAuthProvider(
        FederationProviderConfig config,
        IHttpClientFactory httpClientFactory)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
    }

    public string ProviderId => _config.ProviderId;
    public string DisplayName => _config.DisplayName;
    public int Priority => _config.Priority;

    public Task<FederationChallenge> CreateChallengeAsync(
        string callbackUrl, string returnUrl, CancellationToken ct = default)
    {
        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = ComputeCodeChallenge(codeVerifier);
        var state = GenerateNonce();

        // GitHub uses space-separated scopes per RFC 6749. Ensure user:email is present
        // so we can fetch a verified primary email even when the user's profile email
        // is set to private.
        var scopes = _config.Scopes.Length == 0
            ? new[] { "read:user", "user:email" }
            : (Array.IndexOf(_config.Scopes, "user:email") >= 0
                ? _config.Scopes
                : _config.Scopes.Concat(new[] { "user:email" }).ToArray());

        var authUrl = AuthorizeEndpoint
            + "?response_type=code"
            + "&client_id=" + Uri.EscapeDataString(_config.ClientId)
            + "&redirect_uri=" + Uri.EscapeDataString(callbackUrl)
            + "&scope=" + Uri.EscapeDataString(string.Join(" ", scopes))
            + "&state=" + Uri.EscapeDataString(state)
            + "&code_challenge=" + Uri.EscapeDataString(codeChallenge)
            + "&code_challenge_method=S256"
            + "&allow_signup=true";

        return Task.FromResult(new FederationChallenge
        {
            RedirectUri = authUrl,
            State = state,
            // Nonce intentionally null — GitHub has no id_token to bind it to.
            Nonce = null,
            CodeVerifier = codeVerifier,
        });
    }

    public async Task<ExternalAuthResult> HandleCallbackAsync(
        string code, string callbackUrl, string? codeVerifier = null, string? nonce = null,
        CancellationToken ct = default)
    {
        var http = _httpClientFactory.CreateClient("redb-identity-federation");

        // 1. Exchange code → access_token
        using var tokenReq = new HttpRequestMessage(HttpMethod.Post, TokenEndpoint);
        tokenReq.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = callbackUrl,
            ["client_id"] = _config.ClientId,
            ["client_secret"] = _config.ClientSecret,
        };
        if (!string.IsNullOrEmpty(codeVerifier))
            form["code_verifier"] = codeVerifier;
        tokenReq.Content = new FormUrlEncodedContent(form);

        using var tokenResp = await http.SendAsync(tokenReq, ct).ConfigureAwait(false);
        if (!tokenResp.IsSuccessStatusCode)
            return ExternalAuthResult.Failed($"GitHub token exchange failed: HTTP {(int)tokenResp.StatusCode}");

        var token = await tokenResp.Content.ReadFromJsonAsync<GitHubTokenResponse>(cancellationToken: ct)
            .ConfigureAwait(false);
        if (token is null || string.IsNullOrEmpty(token.access_token))
        {
            // GitHub returns 200 + {"error":"bad_verification_code"} on most failures, hence the explicit check.
            return ExternalAuthResult.Failed("GitHub token exchange returned no access_token.");
        }

        // 2. Fetch user profile
        var profile = await GetJsonAsync<GitHubUser>(http, UserEndpoint, token.access_token, ct).ConfigureAwait(false);
        if (profile is null || profile.id <= 0)
            return ExternalAuthResult.Failed("GitHub /user returned no usable profile.");

        // 3. Resolve verified primary email (profile.email may be null when private).
        string? email = profile.email;
        if (string.IsNullOrEmpty(email))
        {
            var emails = await GetJsonAsync<GitHubEmail[]>(http, EmailsEndpoint, token.access_token, ct)
                .ConfigureAwait(false);
            email = emails?
                .Where(e => e is { verified: true })
                .OrderByDescending(e => e.primary)
                .Select(e => e.email)
                .FirstOrDefault();
        }

        var displayName = !string.IsNullOrWhiteSpace(profile.name) ? profile.name : profile.login;

        return ExternalAuthResult.Success(
            externalId: profile.id.ToString(System.Globalization.CultureInfo.InvariantCulture),
            displayName: displayName,
            email: email,
            additionalClaims: new Dictionary<string, string>
            {
                ["github:login"] = profile.login ?? string.Empty,
                ["github:id"] = profile.id.ToString(System.Globalization.CultureInfo.InvariantCulture),
            });
    }

    private static async Task<T?> GetJsonAsync<T>(HttpClient http, string url, string accessToken, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        // GitHub requires a non-empty User-Agent on every API request.
        req.Headers.UserAgent.ParseAdd("redb.Identity/1.0");
        using var resp = await http.SendAsync(req, ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode) return default;
        return await resp.Content.ReadFromJsonAsync<T>(cancellationToken: ct).ConfigureAwait(false);
    }

    // ── PKCE / state helpers (mirror OidcFederatedAuthProvider) ──
    private static string GenerateCodeVerifier()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Base64UrlEncoder.Encode(bytes);
    }

    private static string ComputeCodeChallenge(string codeVerifier)
    {
        var bytes = SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(codeVerifier));
        return Base64UrlEncoder.Encode(bytes);
    }

    private static string GenerateNonce()
    {
        var bytes = new byte[16];
        RandomNumberGenerator.Fill(bytes);
        return Base64UrlEncoder.Encode(bytes);
    }

    // ── DTOs ──
    private sealed class GitHubTokenResponse
    {
        public string? access_token { get; set; }
        public string? token_type { get; set; }
        public string? scope { get; set; }
    }

    private sealed class GitHubUser
    {
        public long id { get; set; }
        public string? login { get; set; }
        public string? name { get; set; }
        public string? email { get; set; }
    }

    private sealed class GitHubEmail
    {
        public string email { get; set; } = string.Empty;
        public bool primary { get; set; }
        public bool verified { get; set; }
        public string? visibility { get; set; }
    }
}
