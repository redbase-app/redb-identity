using System.Text;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Contracts.Routes;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.TokenFlow;

/// <summary>
/// Integration tests for ROPC (password) flow using the PRODUCTION bootstrap.
/// Real PostgreSQL stores, real OpenIddict pipeline, no degraded mode, no mocks.
/// Requires <see cref="ProductionBootstrapFixture"/> with <c>EnablePasswordFlow = true</c>.
/// </summary>
[Collection("ProductionBootstrap")]
public class ProductionPasswordFlowTests
{
    private readonly ProductionBootstrapFixture _fx;

    public ProductionPasswordFlowTests(ProductionBootstrapFixture fx) => _fx = fx;

    [Fact]
    public async Task ValidCredentials_ReturnsAccessToken()
    {
        var body = new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = ProductionBootstrapFixture.TestUsername,
            ["password"] = ProductionBootstrapFixture.TestPassword,
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret
        };

        var result = await _fx.Request(IdentityEndpoints.Token, body);

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().NotContainKey("error",
            because: $"ROPC should succeed, got: {(response.ContainsKey("error_description") ? response["error_description"] : "n/a")}");
        response.Should().ContainKey("access_token");
        response["access_token"]!.ToString().Should().NotBeEmpty();
        response["token_type"].Should().Be("Bearer");
        response["expires_in"].Should().NotBeNull();
    }

    [Fact]
    public async Task ValidCredentials_JwtContainsUserClaims()
    {
        var body = new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = ProductionBootstrapFixture.TestUsername,
            ["password"] = ProductionBootstrapFixture.TestPassword,
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret,
            ["scope"] = "openid profile email phone"
        };

        var result = await _fx.Request(IdentityEndpoints.Token, body);

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().NotContainKey("error");
        var accessToken = response["access_token"]!.ToString()!;

        var parts = accessToken.Split('.');
        parts.Length.Should().BeGreaterOrEqualTo(3, "access_token should be a JWT");

        var payloadJson = Encoding.UTF8.GetString(
            Convert.FromBase64String(PadBase64(parts[1])));
        var claims = JsonSerializer.Deserialize<JsonElement>(payloadJson);

        claims.TryGetProperty("iss", out var iss).Should().BeTrue("JWT should contain iss");
        iss.GetString().Should().Be("https://identity.test.local/");

        claims.TryGetProperty("sub", out var sub).Should().BeTrue("JWT should contain sub");
        sub.GetString().Should().Be(_fx.TestSubjectGuid.ToString("D"),
            "the public sub claim is the per-user GUID stored on UserProps.value_guid");

        claims.TryGetProperty("redb:user_id", out var internalUid).Should().BeTrue(
            "access token must mirror the bigint _users._id into the internal claim");
        internalUid.GetString().Should().Be(_fx.TestUserId.ToString());

        claims.TryGetProperty("name", out var name).Should().BeTrue("JWT should contain name");
        name.GetString().Should().Be(ProductionBootstrapFixture.TestUsername);

        claims.TryGetProperty("given_name", out var gn).Should().BeTrue("JWT should contain given_name");
        gn.GetString().Should().Be("Test");

        claims.TryGetProperty("family_name", out var fn).Should().BeTrue("JWT should contain family_name");
        fn.GetString().Should().Be("User");

        claims.TryGetProperty("email", out var email).Should().BeTrue("JWT should contain email");
        email.GetString().Should().Be("testuser@example.com");
    }

    [Fact]
    public async Task WrongPassword_ReturnsAccessDenied()
    {
        var body = new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = ProductionBootstrapFixture.TestUsername,
            ["password"] = "WrongPassword!99",
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret
        };

        var result = await _fx.Request(IdentityEndpoints.Token, body);

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().ContainKey("error");
        response["error"].Should().Be("access_denied");
    }

    [Fact]
    public async Task UnknownUser_ReturnsAccessDenied()
    {
        var body = new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = "nonexistent-user",
            ["password"] = "any-password",
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret
        };

        var result = await _fx.Request(IdentityEndpoints.Token, body);

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().ContainKey("error");
        response["error"].Should().Be("access_denied");
    }

    [Fact]
    public async Task MissingClientCredentials_ReturnsInvalidClient()
    {
        var body = new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = ProductionBootstrapFixture.TestUsername,
            ["password"] = ProductionBootstrapFixture.TestPassword
            // No client_id / client_secret
        };

        var result = await _fx.Request(IdentityEndpoints.Token, body);

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().ContainKey("error");
        // Without client credentials, OpenIddict rejects with invalid_client
        response["error"].Should().BeOneOf("invalid_client", "invalid_request");
    }

    [Fact]
    public async Task WrongClientSecret_ReturnsInvalidClient()
    {
        var body = new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = ProductionBootstrapFixture.TestUsername,
            ["password"] = ProductionBootstrapFixture.TestPassword,
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = "wrong-secret"
        };

        var result = await _fx.Request(IdentityEndpoints.Token, body);

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().ContainKey("error");
        response["error"].Should().Be("invalid_client");
    }

    [Fact]
    public async Task PublicClient_WithoutClientSecret_ReturnsError()
    {
        var body = new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = ProductionBootstrapFixture.TestUsername,
            ["password"] = ProductionBootstrapFixture.TestPassword,
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic
            // Public clients don't have a secret
        };

        var result = await _fx.Request(IdentityEndpoints.Token, body);

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        // Public client does not have GrantTypes.Password permission → unauthorized_client
        response.Should().ContainKey("error");
        response["error"].Should().BeOneOf("unauthorized_client", "unsupported_grant_type");
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
}
