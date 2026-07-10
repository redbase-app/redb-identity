using System.Net;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// Z3: RFC 8414 (OAuth 2.0 Authorization Server Metadata) §2 compliance.
/// Asserts that <c>/.well-known/oauth-authorization-server</c> — and the equivalent
/// <c>/.well-known/openid-configuration</c> document — expose every mandatory field
/// with the correct shape. Also verifies that <c>registration_endpoint</c> is advertised
/// when DCR is enabled.
/// </summary>
[Collection("ProductionHttp")]
public class OAuthMetadataComplianceTests
{
    private readonly ProductionHttpFixture _fx;
    private readonly HttpClient _http;

    public OAuthMetadataComplianceTests(ProductionHttpFixture fx)
    {
        _fx = fx;
        _http = fx.Http;
    }

    [Theory]
    [InlineData("/.well-known/oauth-authorization-server")]
    [InlineData("/.well-known/openid-configuration")]
    public async Task Metadata_Document_Declares_All_Mandatory_Fields(string path)
    {
        var resp = await _http.GetAsync(path);
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        resp.Content.Headers.ContentType!.MediaType.Should().Be("application/json");

        var json = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;

        // RFC 8414 §2: issuer MUST be a URL using "https" scheme and no query/fragment.
        json.TryGetProperty("issuer", out var issuer).Should().BeTrue("RFC 8414 §2: issuer REQUIRED");
        issuer.ValueKind.Should().Be(JsonValueKind.String);

        // RFC 8414 §2: authorization_endpoint MUST be present (except for grant_types that do not use it).
        json.TryGetProperty("authorization_endpoint", out var authEndpoint)
            .Should().BeTrue("RFC 8414 §2: authorization_endpoint REQUIRED when supported grant types need it");
        authEndpoint.ValueKind.Should().Be(JsonValueKind.String);
        IsAbsoluteHttp(authEndpoint.GetString()!).Should().BeTrue();

        // RFC 8414 §2: token_endpoint MUST be present (except for implicit-only servers — we support token grants).
        json.TryGetProperty("token_endpoint", out var tokenEndpoint)
            .Should().BeTrue("RFC 8414 §2: token_endpoint REQUIRED when supported grant types use it");
        IsAbsoluteHttp(tokenEndpoint.GetString()!).Should().BeTrue();

        // RFC 8414 §2: jwks_uri is RECOMMENDED when JWTs are issued (we do).
        json.TryGetProperty("jwks_uri", out var jwks).Should().BeTrue(
            "JWTs are issued — jwks_uri RECOMMENDED per RFC 8414 §2");
        IsAbsoluteHttp(jwks.GetString()!).Should().BeTrue();

        // RFC 8414 §2: response_types_supported — REQUIRED; JSON array of strings.
        json.TryGetProperty("response_types_supported", out var rts).Should().BeTrue(
            "RFC 8414 §2: response_types_supported REQUIRED");
        rts.ValueKind.Should().Be(JsonValueKind.Array);
        rts.GetArrayLength().Should().BeGreaterThan(0);

        // grant_types_supported — OPTIONAL but strongly recommended; if present must include at least one string.
        if (json.TryGetProperty("grant_types_supported", out var gts))
        {
            gts.ValueKind.Should().Be(JsonValueKind.Array);
            gts.GetArrayLength().Should().BeGreaterThan(0);
        }

        // token_endpoint_auth_methods_supported — RFC 8414 §2 OPTIONAL; when present, array of strings.
        if (json.TryGetProperty("token_endpoint_auth_methods_supported", out var teams))
        {
            teams.ValueKind.Should().Be(JsonValueKind.Array);
        }

        // scopes_supported — RFC 8414 §2 RECOMMENDED; array of strings.
        if (json.TryGetProperty("scopes_supported", out var scopes))
        {
            scopes.ValueKind.Should().Be(JsonValueKind.Array);
            scopes.GetArrayLength().Should().BeGreaterThan(0);
        }
    }

    [Fact]
    public async Task Metadata_Advertises_RegistrationEndpoint_When_Dcr_Enabled()
    {
        // ProductionHttpFixture enables dynamic registration → RFC 7591 §3 requires advertising the endpoint.
        var resp = await _http.GetAsync("/.well-known/oauth-authorization-server");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var json = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;

        json.TryGetProperty("registration_endpoint", out var reg).Should().BeTrue(
            "RFC 7591 §3: registration_endpoint MUST be advertised when DCR is supported");
        IsAbsoluteHttp(reg.GetString()!).Should().BeTrue();
        reg.GetString().Should().EndWith("/connect/register");
    }

    [Fact]
    public async Task Rfc8414_And_Oidc_Metadata_Share_Issuer_And_CoreEndpoints()
    {
        var oauth = await GetJson("/.well-known/oauth-authorization-server");
        var oidc = await GetJson("/.well-known/openid-configuration");

        oauth.GetProperty("issuer").GetString().Should().Be(oidc.GetProperty("issuer").GetString());
        oauth.GetProperty("token_endpoint").GetString().Should().Be(oidc.GetProperty("token_endpoint").GetString());
        oauth.GetProperty("authorization_endpoint").GetString().Should().Be(oidc.GetProperty("authorization_endpoint").GetString());
        oauth.GetProperty("jwks_uri").GetString().Should().Be(oidc.GetProperty("jwks_uri").GetString());
    }

    private static bool IsAbsoluteHttp(string s)
        => Uri.TryCreate(s, UriKind.Absolute, out var u) && (u.Scheme == "http" || u.Scheme == "https");

    private async Task<JsonElement> GetJson(string path)
    {
        var resp = await _http.GetAsync(path);
        resp.EnsureSuccessStatusCode();
        return JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
    }
}
