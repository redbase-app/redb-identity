using System.Net;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Http.E2E;

/// <summary>
/// E2E tests for Discovery and JWKS endpoints over real HTTP.
/// Validates OpenID Connect Discovery 1.0 and RFC 7517 (JWK Set) compliance.
/// </summary>
[Collection("HttpIdentity")]
public class DiscoveryJwksE2ETests
{
    private readonly HttpClient _http;

    public DiscoveryJwksE2ETests(HttpIdentityFixture fixture) => _http = fixture.Http;

    // ── Discovery ──

    [Fact]
    public async Task Discovery_ReturnsJson_WithCorrectContentType()
    {
        var response = await _http.GetAsync("/.well-known/openid-configuration");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Content.Headers.ContentType!.MediaType.Should().Be("application/json");
    }

    [Fact]
    public async Task Discovery_ContainsIssuer()
    {
        var json = await GetDiscovery();

        json.TryGetProperty("issuer", out var issuer).Should().BeTrue(
            "discovery must contain 'issuer'");
        issuer.GetString().Should().Contain("localhost",
            "issuer should match the configured base URL");
    }

    [Fact]
    public async Task Discovery_ContainsTokenEndpoint()
    {
        var json = await GetDiscovery();

        json.TryGetProperty("token_endpoint", out var ep).Should().BeTrue();
        ep.GetString().Should().Contain("/connect/token");
    }

    [Fact]
    public async Task Discovery_ContainsIntrospectionEndpoint()
    {
        var json = await GetDiscovery();

        json.TryGetProperty("introspection_endpoint", out var ep).Should().BeTrue(
            "discovery must advertise introspection endpoint for resource servers");
        ep.GetString().Should().Contain("/connect/introspect");
    }

    [Fact]
    public async Task Discovery_ContainsRevocationEndpoint()
    {
        var json = await GetDiscovery();

        json.TryGetProperty("revocation_endpoint", out var ep).Should().BeTrue(
            "discovery must advertise revocation endpoint");
        ep.GetString().Should().Contain("/connect/revok");
    }

    [Fact]
    public async Task Discovery_ContainsJwksUri()
    {
        var json = await GetDiscovery();

        json.TryGetProperty("jwks_uri", out var uri).Should().BeTrue();
        uri.GetString().Should().Contain("/.well-known/jwks");
    }

    [Fact]
    public async Task Discovery_ContainsGrantTypesSupported()
    {
        var json = await GetDiscovery();

        json.TryGetProperty("grant_types_supported", out var grants).Should().BeTrue();
        var grantList = grants.EnumerateArray().Select(g => g.GetString()).ToList();
        grantList.Should().Contain("client_credentials");
    }

    [Fact]
    public async Task Discovery_ContainsResponseTypesSupported()
    {
        var json = await GetDiscovery();

        json.TryGetProperty("response_types_supported", out var types).Should().BeTrue(
            "OpenID Connect Discovery 1.0 §3: response_types_supported is REQUIRED");
        var typeList = types.EnumerateArray().Select(t => t.GetString()).ToList();
        typeList.Should().Contain("code",
            "authorization_code flow is enabled — 'code' must be advertised");
    }

    // ── Discovery: conditional feature endpoints ──

    [Fact]
    public async Task Discovery_DoesNotContainRegistrationEndpoint_WhenDisabled()
    {
        var json = await GetDiscovery();

        json.TryGetProperty("registration_endpoint", out _).Should().BeFalse(
            "registration_endpoint must NOT appear when EnableDynamicRegistration=false");
    }

    [Fact]
    public async Task Discovery_DoesNotContainDeviceAuthorizationEndpoint_WhenDisabled()
    {
        var json = await GetDiscovery();

        json.TryGetProperty("device_authorization_endpoint", out _).Should().BeFalse(
            "device_authorization_endpoint must NOT appear when EnableDeviceCodeFlow=false");
    }

    [Fact]
    public async Task Discovery_GrantTypes_DoNotContainDeviceCode_WhenDisabled()
    {
        var json = await GetDiscovery();

        json.TryGetProperty("grant_types_supported", out var grants).Should().BeTrue();
        var grantList = grants.EnumerateArray().Select(g => g.GetString()).ToList();
        grantList.Should().NotContain("urn:ietf:params:oauth:grant-type:device_code",
            "device_code grant type must NOT be advertised when EnableDeviceCodeFlow=false");
    }

    // ── JWKS ──

    [Fact]
    public async Task Jwks_ReturnsJson_WithCorrectContentType()
    {
        var response = await _http.GetAsync("/.well-known/jwks");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Content.Headers.ContentType!.MediaType.Should().Be("application/json");
    }

    [Fact]
    public async Task Jwks_ContainsAtLeastOneKey()
    {
        var json = await GetJsonElement("/.well-known/jwks");

        json.TryGetProperty("keys", out var keys).Should().BeTrue(
            "JWKS must contain 'keys' array");
        keys.ValueKind.Should().Be(JsonValueKind.Array,
            "'keys' must be a JSON array, not a serialized string");
        keys.GetArrayLength().Should().BeGreaterThan(0,
            "server must expose at least one signing key");
    }

    [Fact]
    public async Task Jwks_KeysContainRequiredJwkFields()
    {
        var json = await GetJsonElement("/.well-known/jwks");
        var keys = json.GetProperty("keys");

        keys.ValueKind.Should().Be(JsonValueKind.Array);

        foreach (var key in keys.EnumerateArray())
        {
            // RFC 7517 §4: 'kty' is required
            key.TryGetProperty("kty", out _).Should().BeTrue(
                "each JWK must have 'kty' (key type)");
        }
    }

    // ── Helpers ──

    private async Task<JsonElement> GetDiscovery()
        => await GetJsonElement("/.well-known/openid-configuration");

    private async Task<JsonElement> GetJsonElement(string url)
    {
        var response = await _http.GetAsync(url);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadAsStringAsync();
        return JsonDocument.Parse(body).RootElement;
    }
}
