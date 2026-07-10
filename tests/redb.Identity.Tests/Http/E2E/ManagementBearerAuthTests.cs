using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Http.E2E;

/// <summary>
/// E2E tests for management API bearer token authentication.
/// Exercises the full pipeline: HTTP request → ManagementBearerAuthProcessor
/// → OpenIddict Validation (server-local) → scope check.
/// </summary>
[Collection("HttpIdentity")]
public class ManagementBearerAuthTests
{
    private readonly HttpIdentityFixture _fixture;
    private readonly HttpClient _http;

    public ManagementBearerAuthTests(HttpIdentityFixture fixture)
    {
        _fixture = fixture;
        _http = fixture.Http;
    }

    [Fact]
    public async Task ValidToken_CorrectScope_AllowsAccess()
    {
        var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/identity/applications");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fixture.ManagementToken);

        var response = await _http.SendAsync(req);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task NoAuthorizationHeader_Returns401()
    {
        var response = await _http.GetAsync("/api/v1/identity/applications");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        var body = await ReadErrorBody(response);
        body.GetProperty("error").GetString().Should().Be("missing_token");
    }

    [Fact]
    public async Task BearerInQueryParameter_NoHeader_Returns401()
    {
        // RFC 6750 §2.3: query-parameter bearer transport is deprecated.
        // The management API only honours Authorization: Bearer; even a syntactically
        // valid token presented via ?access_token= must not authorise the request.
        // Source: G9 / D6.
        var url = $"/api/v1/identity/applications?access_token={Uri.EscapeDataString(_fixture.ManagementToken)}";

        var response = await _http.GetAsync(url);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            "query-string bearer must NOT be accepted on the management API");
        var body = await ReadErrorBody(response);
        body.GetProperty("error").GetString().Should().Be("missing_token");
    }

    [Fact]
    public async Task InvalidToken_GarbageString_Returns401()
    {
        var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/identity/applications");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "not-a-valid-token");

        var response = await _http.SendAsync(req);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        var body = await ReadErrorBody(response);
        body.GetProperty("error").GetString().Should().Be("invalid_token");
    }

    [Fact]
    public async Task EmptyBearerToken_Returns401()
    {
        var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/identity/applications");
        req.Headers.TryAddWithoutValidation("Authorization", "Bearer ");

        var response = await _http.SendAsync(req);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task WrongScheme_BasicAuth_Returns401()
    {
        var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/identity/applications");
        req.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic", Convert.ToBase64String("user:pass"u8));

        var response = await _http.SendAsync(req);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        var body = await ReadErrorBody(response);
        body.GetProperty("error").GetString().Should().Be("missing_token");
    }

    [Fact]
    public async Task TokenWithoutManageScope_Returns403()
    {
        // Issue a token WITHOUT identity:manage scope
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "no-scope-client",
            ["client_secret"] = "some-secret",
            ["scope"] = "openid profile"
        });

        var tokenResp = await _http.PostAsync("/connect/token", content);
        tokenResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var tokenJson = await JsonSerializer.DeserializeAsync<JsonElement>(
            await tokenResp.Content.ReadAsStreamAsync());
        var token = tokenJson.GetProperty("access_token").GetString()!;

        // Use the limited token for management API
        var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/identity/applications");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await _http.SendAsync(req);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        var body = await ReadErrorBody(response);
        body.GetProperty("error").GetString().Should().Be("insufficient_scope");
    }

    [Fact]
    public async Task AllManagementEndpoints_RequireBearerToken()
    {
        // All management paths should reject unauthenticated requests
        var paths = new[]
        {
            "/api/v1/identity/applications",
            "/api/v1/identity/scopes",
            "/api/v1/identity/users",
            "/api/v1/identity/tokens",
            "/api/v1/identity/groups"
        };

        foreach (var path in paths)
        {
            var response = await _http.GetAsync(path);
            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
                $"GET {path} should require bearer token");
        }
    }

    [Fact]
    public async Task ValidToken_PostRequest_Works()
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/identity/applications")
        {
            Content = JsonContent.Create(new
            {
                clientId = $"auth-test-{Guid.NewGuid():N}",
                clientSecret = "test-secret",
                displayName = "Auth Test App"
            })
        };
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fixture.ManagementToken);

        var response = await _http.SendAsync(req);

        response.StatusCode.Should().Be(HttpStatusCode.OK,
            "POST with valid bearer token should succeed");
    }

    private static async Task<JsonElement> ReadErrorBody(HttpResponseMessage response)
    {
        var stream = await response.Content.ReadAsStreamAsync();
        return await JsonSerializer.DeserializeAsync<JsonElement>(stream);
    }
}
