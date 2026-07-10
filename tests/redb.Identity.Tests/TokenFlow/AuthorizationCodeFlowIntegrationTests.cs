using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using redb.Identity.Contracts.Routes;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.TokenFlow;

/// <summary>
/// Integration tests for authorization_code + PKCE flow using PRODUCTION bootstrap.
/// Real PostgreSQL stores, real OpenIddict pipeline — no degraded mode.
/// Validates Phase 2 criteria #2: authorization_code + PKCE → tokens.
/// </summary>
[Collection("ProductionBootstrap")]
public class AuthorizationCodeFlowIntegrationTests
{
    private readonly ProductionBootstrapFixture _fx;

    public AuthorizationCodeFlowIntegrationTests(ProductionBootstrapFixture fx) => _fx = fx;

    [Fact]
    public async Task AuthorizeRequest_WithValidCredentials_ReturnsCode()
    {
        var (codeVerifier, codeChallenge) = GeneratePkce();

        var body = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic,
            ["redirect_uri"] = ProductionBootstrapFixture.TestRedirectUri,
            ["scope"] = "openid offline_access",
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256"
        };

        var result = await _fx.RequestWithSession(IdentityEndpoints.Authorize, body);

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().NotContainKey("error",
            because: $"authorize should succeed, got: {(response.ContainsKey("error_description") ? response["error_description"] : "n/a")}");
        response.Should().ContainKey("code", "authorization should return a code");
        response["code"]!.ToString().Should().NotBeEmpty();
    }

    [Fact]
    public async Task FullCodeExchange_ReturnsAccessAndRefreshTokens()
    {
        // Step 1: Get authorization code
        var (codeVerifier, codeChallenge) = GeneratePkce();

        var authorizeBody = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic,
            ["redirect_uri"] = ProductionBootstrapFixture.TestRedirectUri,
            ["scope"] = "openid offline_access",
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256"
        };

        var authorizeResult = await _fx.RequestWithSession(IdentityEndpoints.Authorize, authorizeBody);
        var authorizeResponse = authorizeResult.Should().BeOfType<Dictionary<string, object?>>().Subject;
        authorizeResponse.Should().ContainKey("code",
            because: $"authorize should return code, got: {(authorizeResponse.ContainsKey("error") ? authorizeResponse["error"] : "missing code")}");
        var code = authorizeResponse["code"]!.ToString()!;

        // Step 2: Exchange code for tokens
        var tokenBody = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = ProductionBootstrapFixture.TestRedirectUri,
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic,
            ["code_verifier"] = codeVerifier
        };

        var tokenResult = await _fx.Request(IdentityEndpoints.Token, tokenBody);
        var tokenResponse = tokenResult.Should().BeOfType<Dictionary<string, object?>>().Subject;

        tokenResponse.Should().NotContainKey("error",
            because: $"token exchange should succeed, got: {(tokenResponse.ContainsKey("error_description") ? tokenResponse["error_description"] : "n/a")}");
        tokenResponse.Should().ContainKey("access_token");
        tokenResponse["access_token"]!.ToString().Should().NotBeEmpty();
        tokenResponse["token_type"].Should().Be("Bearer");
        tokenResponse.Should().ContainKey("refresh_token", "offline_access scope should grant refresh token");
    }

    [Fact]
    public async Task PKCE_InvalidVerifier_ReturnsInvalidGrant()
    {
        var (_, codeChallenge) = GeneratePkce();

        var authorizeBody = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic,
            ["redirect_uri"] = ProductionBootstrapFixture.TestRedirectUri,
            ["scope"] = "openid",
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256"
        };

        var authorizeResult = await _fx.RequestWithSession(IdentityEndpoints.Authorize, authorizeBody);
        var authorizeResponse = authorizeResult.Should().BeOfType<Dictionary<string, object?>>().Subject;
        authorizeResponse.Should().ContainKey("code");
        var code = authorizeResponse["code"]!.ToString()!;

        // Use WRONG verifier
        var tokenBody = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = ProductionBootstrapFixture.TestRedirectUri,
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic,
            ["code_verifier"] = "completely-wrong-verifier-value-that-wont-match"
        };

        var tokenResult = await _fx.Request(IdentityEndpoints.Token, tokenBody);
        var tokenResponse = tokenResult.Should().BeOfType<Dictionary<string, object?>>().Subject;

        tokenResponse.Should().ContainKey("error");
        tokenResponse["error"].Should().Be("invalid_grant");
    }

    [Fact]
    public async Task CodeReplay_SecondUse_ReturnsInvalidGrant()
    {
        var (codeVerifier, codeChallenge) = GeneratePkce();

        var authorizeBody = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic,
            ["redirect_uri"] = ProductionBootstrapFixture.TestRedirectUri,
            ["scope"] = "openid",
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256"
        };

        var authorizeResult = await _fx.RequestWithSession(IdentityEndpoints.Authorize, authorizeBody);
        var authorizeResponse = authorizeResult.Should().BeOfType<Dictionary<string, object?>>().Subject;
        var code = authorizeResponse["code"]!.ToString()!;

        var tokenBody = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = ProductionBootstrapFixture.TestRedirectUri,
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic,
            ["code_verifier"] = codeVerifier
        };

        // First use — should succeed
        var firstResult = await _fx.Request(IdentityEndpoints.Token, tokenBody);
        var firstResponse = firstResult.Should().BeOfType<Dictionary<string, object?>>().Subject;
        firstResponse.Should().ContainKey("access_token", "first code exchange should succeed");

        // Second use — should fail (replay)
        var secondResult = await _fx.Request(IdentityEndpoints.Token, tokenBody);
        var secondResponse = secondResult.Should().BeOfType<Dictionary<string, object?>>().Subject;
        secondResponse.Should().ContainKey("error");
        // OpenIddict returns invalid_token for replayed authorization codes
        secondResponse["error"]!.ToString().Should().Contain("invalid");
    }

    [Fact]
    public async Task InvalidSession_ReturnsDenied()
    {
        var (_, codeChallenge) = GeneratePkce();

        var body = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic,
            ["redirect_uri"] = ProductionBootstrapFixture.TestRedirectUri,
            ["scope"] = "openid",
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256"
        };

        // Use a non-existent user ID in the session header
        var headers = new Dictionary<string, object?>
        {
            ["session_user_id"] = -99999L,
            ["session_username"] = "nonexistent"
        };
        var exchange = await _fx.RequestWithHeaders(IdentityEndpoints.Authorize, body, headers);
        var result = exchange.HasOut ? exchange.Out!.Body : exchange.In.Body;
        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;

        response.Should().ContainKey("error");
        response["error"].Should().Be("login_required");
    }

    [Fact]
    public async Task MissingCredentials_ReturnsLoginRequired()
    {
        var (_, codeChallenge) = GeneratePkce();

        var body = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic,
            ["redirect_uri"] = ProductionBootstrapFixture.TestRedirectUri,
            ["scope"] = "openid",
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256"
            // No username/password
        };

        var result = await _fx.Request(IdentityEndpoints.Authorize, body);
        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;

        response.Should().ContainKey("error");
        response["error"].Should().Be("login_required");
    }

    [Fact]
    public async Task RedirectUriMismatch_ReturnsError()
    {
        var (_, codeChallenge) = GeneratePkce();

        var body = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic,
            ["redirect_uri"] = "http://evil.example.com/callback",
            ["scope"] = "openid",
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256"
        };

        var result = await _fx.RequestWithSession(IdentityEndpoints.Authorize, body);
        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;

        response.Should().ContainKey("error");
    }

    [Fact]
    public async Task ConfidentialClient_AuthCodeFlow_Works()
    {
        var (codeVerifier, codeChallenge) = GeneratePkce();

        // Authorize with confidential client
        var authorizeBody = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["redirect_uri"] = ProductionBootstrapFixture.TestRedirectUri,
            ["scope"] = "openid",
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256"
        };

        var authorizeResult = await _fx.RequestWithSession(IdentityEndpoints.Authorize, authorizeBody);
        var authorizeResponse = authorizeResult.Should().BeOfType<Dictionary<string, object?>>().Subject;
        authorizeResponse.Should().ContainKey("code",
            because: $"authorize should work, got: {(authorizeResponse.ContainsKey("error") ? authorizeResponse["error"] : "missing code")}");
        var code = authorizeResponse["code"]!.ToString()!;

        // Token exchange with client_secret (confidential)
        var tokenBody = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = ProductionBootstrapFixture.TestRedirectUri,
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret,
            ["code_verifier"] = codeVerifier
        };

        var tokenResult = await _fx.Request(IdentityEndpoints.Token, tokenBody);
        var tokenResponse = tokenResult.Should().BeOfType<Dictionary<string, object?>>().Subject;

        tokenResponse.Should().NotContainKey("error",
            because: $"token exchange should succeed, got: {(tokenResponse.ContainsKey("error_description") ? tokenResponse["error_description"] : "n/a")}");
        tokenResponse.Should().ContainKey("access_token");
    }

    private static (string codeVerifier, string codeChallenge) GeneratePkce()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        var verifier = Convert.ToBase64String(bytes)
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        var challenge = Convert.ToBase64String(hash)
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        return (verifier, challenge);
    }
}
