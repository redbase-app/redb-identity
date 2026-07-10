using FluentAssertions;
using redb.Identity.Contracts.Routes;
using redb.Identity.Tests.Infrastructure;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace redb.Identity.Tests.TokenFlow;

/// <summary>
/// Integration tests for the /connect/userinfo endpoint.
/// Validates profile claims (email, phone, given_name, family_name) are returned
/// based on requested scopes. Real PostgreSQL, real OpenIddict pipeline.
/// </summary>
[Collection("ProductionBootstrap")]
public class UserinfoIntegrationTests
{
    private readonly ProductionBootstrapFixture _fx;

    public UserinfoIntegrationTests(ProductionBootstrapFixture fx) => _fx = fx;

    [Fact]
    public async Task Userinfo_WithProfileScope_ReturnsNameClaims()
    {
        var accessToken = await ObtainAccessToken("openid profile");

        var exchange = await _fx.RequestWithHeaders(
            IdentityEndpoints.Userinfo,
            null,
            new Dictionary<string, object?> { ["Authorization"] = $"Bearer {accessToken}" });

        var response = exchange.Out?.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        response.Should().NotBeNull();
        response.Should().ContainKey("sub");
        response.Should().ContainKey("name");
        response.Should().ContainKey("given_name");
        response!["given_name"].Should().Be("Test");
        response.Should().ContainKey("family_name");
        response["family_name"].Should().Be("User");
    }

    [Fact]
    public async Task Userinfo_WithEmailScope_ReturnsEmailClaims()
    {
        var accessToken = await ObtainAccessToken("openid email");

        var exchange = await _fx.RequestWithHeaders(
            IdentityEndpoints.Userinfo,
            null,
            new Dictionary<string, object?> { ["Authorization"] = $"Bearer {accessToken}" });

        var response = exchange.Out?.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        response.Should().NotBeNull();
        response.Should().ContainKey("sub");
        response.Should().ContainKey("email");
        response!["email"].Should().Be("testuser@example.com");
        response.Should().ContainKey("email_verified");
    }

    [Fact]
    public async Task Userinfo_WithPhoneScope_ReturnsPhoneClaims()
    {
        var accessToken = await ObtainAccessToken("openid phone");

        var exchange = await _fx.RequestWithHeaders(
            IdentityEndpoints.Userinfo,
            null,
            new Dictionary<string, object?> { ["Authorization"] = $"Bearer {accessToken}" });

        var response = exchange.Out?.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        response.Should().NotBeNull();
        response.Should().ContainKey("sub");
        response.Should().ContainKey("phone_number");
        response!["phone_number"].Should().Be("+1234567890");
    }

    [Fact]
    public async Task Userinfo_WithAllScopes_ReturnsFullProfile()
    {
        var accessToken = await ObtainAccessToken("openid profile email phone");

        var exchange = await _fx.RequestWithHeaders(
            IdentityEndpoints.Userinfo,
            null,
            new Dictionary<string, object?> { ["Authorization"] = $"Bearer {accessToken}" });

        var response = exchange.Out?.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        response.Should().NotBeNull();
        response.Should().ContainKey("sub");
        response.Should().ContainKey("name");
        response.Should().ContainKey("given_name");
        response.Should().ContainKey("family_name");
        response.Should().ContainKey("email");
        response.Should().ContainKey("email_verified");
        response.Should().ContainKey("phone_number");
    }

    [Fact]
    public async Task Userinfo_WithOnlyOpenIdScope_ReturnsOnlySub()
    {
        var accessToken = await ObtainAccessToken("openid");

        var exchange = await _fx.RequestWithHeaders(
            IdentityEndpoints.Userinfo,
            null,
            new Dictionary<string, object?> { ["Authorization"] = $"Bearer {accessToken}" });

        var response = exchange.Out?.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        response.Should().NotBeNull();
        response.Should().ContainKey("sub");
        response.Should().NotContainKey("email");
        response.Should().NotContainKey("phone_number");
        response.Should().NotContainKey("given_name");
    }

    [Fact]
    public async Task Userinfo_NoBearerToken_ReturnsError()
    {
        var exchange = await _fx.RequestWithHeaders(
            IdentityEndpoints.Userinfo,
            null,
            new Dictionary<string, object?>());

        var response = exchange.Out?.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        response.Should().NotBeNull();
        response.Should().ContainKey("error");
    }

    /// <summary>
    /// Get access token via auth_code + PKCE flow with the specified scopes.
    /// Retries once on transient database errors.
    /// </summary>
    private async Task<string> ObtainAccessToken(string scopes)
    {
        const int maxRetries = 2;

        for (int attempt = 1; attempt <= maxRetries; attempt++)
        {
            var (codeVerifier, codeChallenge) = GeneratePkce();

            var authorizeBody = new Dictionary<string, string>
            {
                ["response_type"] = "code",
                ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic,
                ["redirect_uri"] = ProductionBootstrapFixture.TestRedirectUri,
                ["scope"] = scopes,
                ["code_challenge"] = codeChallenge,
                ["code_challenge_method"] = "S256"
            };

            var authorizeResult = await _fx.RequestWithSession(IdentityEndpoints.Authorize, authorizeBody);
            var authorizeResponse = (Dictionary<string, object?>)authorizeResult!;

            if (!authorizeResponse.ContainsKey("code"))
            {
                if (attempt < maxRetries)
                {
                    await Task.Delay(500);
                    continue;
                }

                Assert.Fail(
                    $"Authorize response missing 'code' after {maxRetries} attempts. " +
                    $"Values: [{string.Join(", ", authorizeResponse.Select(kv => $"{kv.Key}={kv.Value}"))}]");
            }

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
            return tokenResponse["access_token"]!.ToString()!;
        }

        throw new InvalidOperationException("Unreachable");
    }

    private static (string codeVerifier, string codeChallenge) GeneratePkce()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        var verifier = Convert.ToBase64String(bytes)
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        var challenge = Convert.ToBase64String(hash)
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return (verifier, challenge);
    }
}
