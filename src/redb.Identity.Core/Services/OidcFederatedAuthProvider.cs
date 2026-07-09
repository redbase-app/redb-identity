using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using redb.Identity.Core.Configuration;
using redb.Identity.Contracts.Configuration;

namespace redb.Identity.Core.Services;

/// <summary>
/// Generic OIDC Relying Party — works with any IdP that exposes
/// <c>.well-known/openid-configuration</c> (Google, Azure AD, Keycloak, etc.).
/// Uses PKCE (S256), validates id_token signature + claims.
/// </summary>
public sealed class OidcFederatedAuthProvider : IFederatedAuthProvider
{
    private readonly FederationProviderConfig _config;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ConfigurationManager<OpenIdConnectConfiguration> _configManager;
    private static readonly JsonWebTokenHandler _tokenHandler = new();

    public OidcFederatedAuthProvider(
        FederationProviderConfig config,
        IHttpClientFactory httpClientFactory)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));

        var metadataAddress = config.Authority.TrimEnd('/') + "/.well-known/openid-configuration";
        _configManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            metadataAddress,
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever(_httpClientFactory.CreateClient("redb-identity-federation"))
            {
                RequireHttps = config.Authority.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
            });
    }

    public string ProviderId => _config.ProviderId;
    public string DisplayName => _config.DisplayName;
    public int Priority => _config.Priority;

    public async Task<FederationChallenge> CreateChallengeAsync(
        string callbackUrl, string returnUrl, CancellationToken ct = default)
    {
        var disco = await _configManager.GetConfigurationAsync(ct).ConfigureAwait(false);

        // PKCE S256
        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = ComputeCodeChallenge(codeVerifier);
        var nonce = GenerateNonce();
        var state = GenerateNonce(); // opaque, the caller wraps it with DataProtection

        var authUrl = disco.AuthorizationEndpoint
            + "?response_type=code"
            + "&client_id=" + Uri.EscapeDataString(_config.ClientId)
            + "&redirect_uri=" + Uri.EscapeDataString(callbackUrl)
            + "&scope=" + Uri.EscapeDataString(string.Join(" ", _config.Scopes))
            + "&state=" + Uri.EscapeDataString(state)
            + "&nonce=" + Uri.EscapeDataString(nonce)
            + "&code_challenge=" + Uri.EscapeDataString(codeChallenge)
            + "&code_challenge_method=S256";

        return new FederationChallenge
        {
            RedirectUri = authUrl,
            State = state,
            Nonce = nonce,
            CodeVerifier = codeVerifier
        };
    }

    public async Task<ExternalAuthResult> HandleCallbackAsync(
        string code, string callbackUrl, string? codeVerifier = null, string? nonce = null,
        CancellationToken ct = default)
    {
        var disco = await _configManager.GetConfigurationAsync(ct).ConfigureAwait(false);

        // Exchange authorization code for tokens
        var tokenResponse = await ExchangeCodeAsync(disco.TokenEndpoint, code, callbackUrl, codeVerifier, ct)
            .ConfigureAwait(false);

        if (tokenResponse is null || string.IsNullOrEmpty(tokenResponse.id_token))
            return ExternalAuthResult.Failed("Token exchange failed or no id_token received.");

        // Validate id_token
        var validationResult = await ValidateIdTokenAsync(tokenResponse.id_token, disco, nonce, ct)
            .ConfigureAwait(false);

        if (!validationResult.IsValid)
            return ExternalAuthResult.Failed($"id_token validation failed: {validationResult.Exception?.Message}");

        var claims = validationResult.ClaimsIdentity;
        var sub = claims.FindFirst("sub")?.Value;
        if (string.IsNullOrEmpty(sub))
            return ExternalAuthResult.Failed("id_token missing 'sub' claim.");

        return ExternalAuthResult.Success(
            externalId: sub,
            displayName: claims.FindFirst("name")?.Value,
            email: claims.FindFirst("email")?.Value,
            givenName: claims.FindFirst("given_name")?.Value,
            familyName: claims.FindFirst("family_name")?.Value);
    }

    private async Task<TokenResponse?> ExchangeCodeAsync(
        string tokenEndpoint, string code, string callbackUrl,
        string? codeVerifier, CancellationToken ct)
    {
        using var client = _httpClientFactory.CreateClient("redb-identity-federation");

        var parameters = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = callbackUrl,
            ["client_id"] = _config.ClientId,
            ["client_secret"] = _config.ClientSecret
        };

        if (!string.IsNullOrEmpty(codeVerifier))
            parameters["code_verifier"] = codeVerifier;

        using var content = new FormUrlEncodedContent(parameters);
        using var response = await client.PostAsync(tokenEndpoint, content, ct).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
            return null;

        return await response.Content.ReadFromJsonAsync<TokenResponse>(ct).ConfigureAwait(false);
    }

    private async Task<TokenValidationResult> ValidateIdTokenAsync(
        string idToken, OpenIdConnectConfiguration disco,
        string? expectedNonce, CancellationToken ct)
    {
        var validationParams = new TokenValidationParameters
        {
            ValidIssuer = _config.Authority.TrimEnd('/'),
            ValidAudience = _config.ClientId,
            IssuerSigningKeys = disco.SigningKeys,
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(5)
        };

        var result = await _tokenHandler.ValidateTokenAsync(idToken, validationParams).ConfigureAwait(false);

        // Validate nonce if provided
        if (result.IsValid && !string.IsNullOrEmpty(expectedNonce))
        {
            var tokenNonce = result.ClaimsIdentity.FindFirst("nonce")?.Value;
            if (tokenNonce != expectedNonce)
            {
                return new TokenValidationResult
                {
                    IsValid = false,
                    Exception = new SecurityTokenValidationException("Nonce mismatch in id_token.")
                };
            }
        }

        return result;
    }

    // PKCE helpers
    private static string GenerateCodeVerifier()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Base64UrlEncoder.Encode(bytes);
    }

    private static string ComputeCodeChallenge(string codeVerifier)
    {
        var bytes = SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier));
        return Base64UrlEncoder.Encode(bytes);
    }

    private static string GenerateNonce()
    {
        var bytes = new byte[16];
        RandomNumberGenerator.Fill(bytes);
        return Base64UrlEncoder.Encode(bytes);
    }

    private sealed class TokenResponse
    {
        public string? access_token { get; set; }
        public string? id_token { get; set; }
        public string? token_type { get; set; }
        public int expires_in { get; set; }
    }
}
