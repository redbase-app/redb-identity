using System.Text;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Contracts.Routes;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.TokenFlow;

/// <summary>
/// Integration tests for client_credentials flow using the PRODUCTION bootstrap.
/// Real PostgreSQL stores, real OpenIddict pipeline, no degraded mode, no mocks.
/// Validates Phase 2 criterion #1: client_credentials → valid JWT.
/// </summary>
[Collection("ProductionBootstrap")]
public class ProductionClientCredentialsTests
{
    private readonly ProductionBootstrapFixture _fx;

    public ProductionClientCredentialsTests(ProductionBootstrapFixture fx) => _fx = fx;

    [Fact]
    public async Task ValidClientCredentials_ReturnsAccessToken()
    {
        var body = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret
        };

        var result = await _fx.Request(IdentityEndpoints.Token, body);

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().ContainKey("access_token");
        response["access_token"]!.ToString().Should().NotBeEmpty();
        response["token_type"].Should().Be("Bearer");
        response["expires_in"].Should().NotBeNull();
        response.Should().NotContainKey("error");
    }

    [Fact]
    public async Task ValidClientCredentials_JwtContainsStandardClaims()
    {
        var body = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret,
            ["scope"] = "openid"
        };

        var result = await _fx.Request(IdentityEndpoints.Token, body);
        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        var accessToken = response["access_token"]!.ToString()!;

        // Parse JWT manually (no System.IdentityModel.Tokens.Jwt dependency)
        var parts = accessToken.Split('.');
        parts.Length.Should().BeGreaterOrEqualTo(3, "access_token should be a JWT with header.payload.signature");

        var payloadJson = Encoding.UTF8.GetString(
            Convert.FromBase64String(PadBase64(parts[1])));
        var claims = JsonSerializer.Deserialize<JsonElement>(payloadJson);

        claims.TryGetProperty("iss", out var iss).Should().BeTrue("JWT should contain iss claim");
        iss.GetString().Should().Be("https://identity.test.local/");
        claims.TryGetProperty("sub", out _).Should().BeTrue("JWT should contain sub claim");
    }

    private static string PadBase64(string base64)
    {
        switch (base64.Length % 4)
        {
            case 2: return base64 + "==";
            case 3: return base64 + "=";
            default: return base64;
        }
    }

    [Fact]
    public async Task BasicAuth_ValidCredentials_ReturnsAccessToken()
    {
        var credentials = Convert.ToBase64String(
            System.Text.Encoding.UTF8.GetBytes(
                $"{ProductionBootstrapFixture.TestClientId}:{ProductionBootstrapFixture.TestClientSecret}"));

        var exchange = await _fx.RequestWithHeaders(
            IdentityEndpoints.Token,
            new Dictionary<string, string> { ["grant_type"] = "client_credentials" },
            new Dictionary<string, object?> { ["Authorization"] = $"Basic {credentials}" });

        // After PipelineProcessor fix: final Out is preserved (not merged into In)
        exchange.Out.Should().NotBeNull("token endpoint must produce an Out message");
        var response = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().NotContainKey("error",
            because: $"should succeed, got: {(response.ContainsKey("error_description") ? response["error_description"] : response.ContainsKey("error") ? response["error"] : "n/a")}");
        response.Should().ContainKey("access_token");
    }

    [Fact]
    public async Task InvalidClientSecret_ReturnsInvalidClient()
    {
        var body = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = "wrong-secret"
        };

        var result = await _fx.Request(IdentityEndpoints.Token, body);

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().ContainKey("error");
        response["error"].Should().Be("invalid_client");
    }

    [Fact]
    public async Task UnknownClientId_ReturnsInvalidClient()
    {
        var body = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "nonexistent-client",
            ["client_secret"] = "any-secret"
        };

        var result = await _fx.Request(IdentityEndpoints.Token, body);

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().ContainKey("error");
        response["error"].Should().Be("invalid_client");
    }

    [Fact]
    public async Task UnsupportedGrantType_ReturnsError()
    {
        var body = new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:custom-invalid",
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret
        };

        var result = await _fx.Request(IdentityEndpoints.Token, body);

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().ContainKey("error");
        response["error"].Should().Be("unsupported_grant_type");
    }
}
