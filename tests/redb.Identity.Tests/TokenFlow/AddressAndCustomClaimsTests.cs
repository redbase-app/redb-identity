using FluentAssertions;
using redb.Identity.Contracts.Routes;
using redb.Identity.Tests.Infrastructure;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.TokenFlow;

/// <summary>
/// Integration tests for address claim (OIDC §5.1.1) and custom claims.
/// Real PostgreSQL, real OpenIddict pipeline.
/// </summary>
[Collection("ProductionBootstrap")]
public class AddressAndCustomClaimsTests
{
    private readonly ProductionBootstrapFixture _fx;
    private readonly ITestOutputHelper _out;

    public AddressAndCustomClaimsTests(ProductionBootstrapFixture fx, ITestOutputHelper o)
    {
        _fx = fx;
        _out = o;
    }

    [Fact]
    public async Task Userinfo_WithAddressScope_ReturnsStructuredAddressClaim()
    {
        var accessToken = await ObtainAccessToken("openid address");

        var exchange = await _fx.RequestWithHeaders(
            IdentityEndpoints.Userinfo,
            null,
            new Dictionary<string, object?> { ["Authorization"] = $"Bearer {accessToken}" });

        var response = exchange.Out?.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        response.Should().NotBeNull();
        response.Should().ContainKey("sub");
        response.Should().ContainKey("address");
        _out.WriteLine($"address claim: {response!["address"]}");

        // address must be a structured object, not a flat string
        var addressObj = response["address"]!;
        var addressDict = addressObj.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        addressDict["street_address"]?.ToString().Should().Be("123 Test Street");
        addressDict["locality"]?.ToString().Should().Be("Testville");
        addressDict["region"]?.ToString().Should().Be("TS");
        addressDict["postal_code"]?.ToString().Should().Be("12345");
        addressDict["country"]?.ToString().Should().Be("US");
    }

    [Fact]
    public async Task Userinfo_WithoutAddressScope_NoAddressClaim()
    {
        var accessToken = await ObtainAccessToken("openid profile");

        var exchange = await _fx.RequestWithHeaders(
            IdentityEndpoints.Userinfo,
            null,
            new Dictionary<string, object?> { ["Authorization"] = $"Bearer {accessToken}" });

        var response = exchange.Out?.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        response.Should().NotBeNull();
        response.Should().ContainKey("sub");
        response.Should().NotContainKey("address");
    }

    [Fact]
    public async Task Userinfo_CustomClaims_ReturnedInResponse()
    {
        var accessToken = await ObtainAccessToken("openid profile");

        var exchange = await _fx.RequestWithHeaders(
            IdentityEndpoints.Userinfo,
            null,
            new Dictionary<string, object?> { ["Authorization"] = $"Bearer {accessToken}" });

        var response = exchange.Out?.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        response.Should().NotBeNull();
        response.Should().ContainKey("department");
        response!["department"].Should().Be("Engineering");
        response.Should().ContainKey("employee_id");
        response["employee_id"].Should().Be("EMP-0042");
    }

    [Fact]
    public async Task Token_WithAddressScope_AccessTokenContainsAddressClaim()
    {
        var accessToken = await ObtainAccessToken("openid address");
        accessToken.Should().NotBeNullOrEmpty();

        // Decode JWT payload (access_token is a JWS)
        var parts = accessToken.Split('.');
        parts.Length.Should().BeGreaterOrEqualTo(3, "access_token should be a JWT");

        var payload = parts[1];
        // Fix base64url padding
        var padded = payload.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        var json = Encoding.UTF8.GetString(Convert.FromBase64String(padded));
        _out.WriteLine($"JWT payload: {json}");

        var claims = JsonSerializer.Deserialize<JsonElement>(json);
        claims.TryGetProperty("address", out var addr).Should().BeTrue("address claim should be in access_token");
        _out.WriteLine($"address in token: {addr}");
    }

    [Fact]
    public async Task Token_CustomClaims_InAccessToken()
    {
        var accessToken = await ObtainAccessToken("openid profile");
        accessToken.Should().NotBeNullOrEmpty();

        var parts = accessToken.Split('.');
        parts.Length.Should().BeGreaterOrEqualTo(3);

        var payload = parts[1].Replace('-', '+').Replace('_', '/');
        switch (payload.Length % 4)
        {
            case 2: payload += "=="; break;
            case 3: payload += "="; break;
        }
        var json = Encoding.UTF8.GetString(Convert.FromBase64String(payload));
        _out.WriteLine($"JWT payload: {json}");

        var claims = JsonSerializer.Deserialize<JsonElement>(json);
        claims.TryGetProperty("department", out var dept).Should().BeTrue("custom claim 'department' should be in access_token");
        dept.GetString().Should().Be("Engineering");
        claims.TryGetProperty("employee_id", out var empId).Should().BeTrue("custom claim 'employee_id' should be in access_token");
        empId.GetString().Should().Be("EMP-0042");
    }

    [Fact]
    public async Task Userinfo_AllScopes_ReturnsAddressAndProfile()
    {
        var accessToken = await ObtainAccessToken("openid profile email phone address");

        var exchange = await _fx.RequestWithHeaders(
            IdentityEndpoints.Userinfo,
            null,
            new Dictionary<string, object?> { ["Authorization"] = $"Bearer {accessToken}" });

        var response = exchange.Out?.Body.Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        response.Should().NotBeNull();
        response.Should().ContainKey("sub");
        response.Should().ContainKey("name");
        response.Should().ContainKey("email");
        response.Should().ContainKey("phone_number");
        response.Should().ContainKey("address");
        response.Should().ContainKey("department");
        response.Should().ContainKey("employee_id");
    }

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
                Assert.Fail($"Authorize missing 'code'. Got: [{string.Join(", ", authorizeResponse.Select(kv => $"{kv.Key}={kv.Value}"))}]");
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
