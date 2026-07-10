using FluentAssertions;
using redb.Identity.Contracts.Routes;
using redb.Identity.Tests.Infrastructure;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace redb.Identity.Tests.TokenFlow;

/// <summary>
/// Integration tests for refresh_token flow using PRODUCTION bootstrap.
/// Real PostgreSQL stores, real OpenIddict pipeline — no degraded mode.
/// Validates Phase 2 criteria #3: refresh_token rotation, revocation, client binding.
/// </summary>
[Collection("ProductionBootstrap")]
public class RefreshTokenFlowIntegrationTests
{
    private readonly ProductionBootstrapFixture _fx;

    public RefreshTokenFlowIntegrationTests(ProductionBootstrapFixture fx) => _fx = fx;

    [Fact]
    public async Task ValidRefreshToken_ReturnsNewAccessToken()
    {
        var (_, refreshToken) = await ObtainTokensViaAuthCodeFlow();

        var refreshBody = new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic
        };

        var result = await _fx.Request(IdentityEndpoints.Token, refreshBody);
        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;

        response.Should().NotContainKey("error",
            because: $"refresh should succeed, got: {(response.ContainsKey("error_description") ? response["error_description"] : "n/a")}");
        response.Should().ContainKey("access_token");
        response["access_token"]!.ToString().Should().NotBeEmpty();
        response["token_type"].Should().Be("Bearer");
    }

    [Fact]
    public async Task RefreshToken_RotatesToken()
    {
        var (_, refreshToken) = await ObtainTokensViaAuthCodeFlow();

        var refreshBody = new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic
        };

        var result = await _fx.Request(IdentityEndpoints.Token, refreshBody);
        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;

        response.Should().ContainKey("refresh_token", "rotation should issue a new refresh token");
        response["refresh_token"]!.ToString().Should().NotBe(refreshToken,
            "new refresh token should differ from old one");
    }

    [Fact]
    public async Task InvalidRefreshToken_ReturnsError()
    {
        var refreshBody = new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = "this-is-not-a-valid-refresh-token",
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic
        };

        var result = await _fx.Request(IdentityEndpoints.Token, refreshBody);
        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;

        response.Should().ContainKey("error");
        // OpenIddict may return invalid_grant or invalid_token for a bogus token
        response["error"]!.ToString().Should().Contain("invalid");
    }

    [Fact]
    public async Task RefreshToken_WrongClient_ReturnsError()
    {
        // Get refresh token for public client
        var (_, refreshToken) = await ObtainTokensViaAuthCodeFlow();

        // Try to use it with the confidential client
        var refreshBody = new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret
        };

        var result = await _fx.Request(IdentityEndpoints.Token, refreshBody);
        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;

        // Should fail — token bound to different client
        response.Should().ContainKey("error");
    }

    [Fact]
    public async Task UsedRefreshToken_AfterRotation_StrictReplay_Fails()
    {
        var (_, refreshToken) = await ObtainTokensViaAuthCodeFlow();

        // First refresh — consumes the old token, issues new pair
        var refreshBody = new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic
        };

        var firstResult = await _fx.Request(IdentityEndpoints.Token, refreshBody);
        var firstResponse = firstResult.Should().BeOfType<Dictionary<string, object?>>().Subject;
        firstResponse.Should().ContainKey("access_token", "first refresh should succeed");

        // Second use of SAME old token — replay attack
        // With RefreshTokenReuseLeeway = TimeSpan.Zero (strict rotation), this MUST fail
        var secondResult = await _fx.Request(IdentityEndpoints.Token, refreshBody);
        var secondResponse = secondResult.Should().BeOfType<Dictionary<string, object?>>().Subject;
        secondResponse.Should().ContainKey("error");
        secondResponse["error"].Should().BeOneOf("invalid_grant", "invalid_token");
    }

    /// <summary>
    /// Helper: full authorization_code + PKCE flow to obtain access_token + refresh_token.
    /// </summary>
    private async Task<(string accessToken, string refreshToken)> ObtainTokensViaAuthCodeFlow()
    {
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
        var authorizeResponse = (Dictionary<string, object?>)authorizeResult!;
        var code = authorizeResponse["code"]!.ToString()!;

        var tokenBody = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = ProductionBootstrapFixture.TestRedirectUri,
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic,
            ["code_verifier"] = codeVerifier
        };

        var tokenResult = await _fx.Request(IdentityEndpoints.Token, tokenBody);
        var tokenResponse = (Dictionary<string, object?>)tokenResult!;

        tokenResponse.Should().ContainKey("access_token", "code exchange must return access_token");
        tokenResponse.Should().ContainKey("refresh_token", "offline_access scope must return refresh_token");

        return (
            tokenResponse["access_token"]!.ToString()!,
            tokenResponse["refresh_token"]!.ToString()!
        );
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
