using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// Full-stack E2E tests for Dynamic Client Registration (RFC 7591).
/// Complete path: HTTP POST /connect/register → Kestrel → HTTP facade → ExtractBearerToken
/// → direct-vm://identity-dynamic-register → Throttle → DynamicRegistrationProcessor
/// → redb stores → PostgreSQL → HTTP 201 response.
/// Then: dynamically registered client authenticates via /connect/token.
/// </summary>
[Collection("ProductionHttp")]
public class FullStackDynamicRegistrationTests
{
    private readonly ProductionHttpFixture _fx;
    private readonly HttpClient _http;

    public FullStackDynamicRegistrationTests(ProductionHttpFixture fx)
    {
        _fx = fx;
        _http = fx.Http;
    }

    // ══════════════════════════════════════════════
    //  Happy path
    // ══════════════════════════════════════════════

    [Fact]
    public async Task Register_MinimalRequest_Returns201WithClientId()
    {
        var req = DynRegRequest(new
        {
            redirect_uris = new[] { "http://localhost/callback" },
            client_name = "E2E Minimal"
        });

        var resp = await _http.SendAsync(req);

        resp.StatusCode.Should().Be(HttpStatusCode.Created,
            "register failed: {0}", await resp.Content.ReadAsStringAsync());

        var json = await ParseJson(resp);
        json.TryGetProperty("client_id", out var cid).Should().BeTrue("response must contain client_id");
        cid.GetString().Should().NotBeNullOrWhiteSpace();
        json.TryGetProperty("client_secret", out _).Should().BeTrue("confidential by default → secret returned");
        json.GetProperty("token_endpoint_auth_method").GetString().Should().Be("client_secret_basic");
        json.TryGetProperty("client_id_issued_at", out _).Should().BeTrue();
    }

    [Fact]
    public async Task Register_PublicClient_NoSecretReturned()
    {
        var req = DynRegRequest(new
        {
            redirect_uris = new[] { "http://localhost/callback" },
            token_endpoint_auth_method = "none",
            client_name = "E2E Public"
        });

        var resp = await _http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.Created);

        var json = await ParseJson(resp);
        json.GetProperty("token_endpoint_auth_method").GetString().Should().Be("none");
        // Public clients should NOT have a secret
        if (json.TryGetProperty("client_secret", out var secret))
            secret.ValueKind.Should().Be(JsonValueKind.Null);
    }

    [Fact]
    public async Task Register_ConfidentialClient_CanObtainToken()
    {
        // Step 1: Register a new confidential client
        var regReq = DynRegRequest(new
        {
            redirect_uris = new[] { "http://localhost/callback" },
            grant_types = new[] { "client_credentials" },
            client_name = "E2E Token Test",
            scope = "openid"
        });

        var regResp = await _http.SendAsync(regReq);
        regResp.StatusCode.Should().Be(HttpStatusCode.Created,
            "register failed: {0}", await regResp.Content.ReadAsStringAsync());

        var regJson = await ParseJson(regResp);
        var clientId = regJson.GetProperty("client_id").GetString()!;
        var clientSecret = regJson.GetProperty("client_secret").GetString()!;

        // Step 2: Use the registered client to obtain an access token
        var tokenContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret
        });

        var tokenResp = await _http.PostAsync("/connect/token", tokenContent);

        tokenResp.StatusCode.Should().Be(HttpStatusCode.OK,
            "token request with dynamically registered client failed: {0}",
            await tokenResp.Content.ReadAsStringAsync());

        var tokenJson = await ParseJson(tokenResp);
        tokenJson.TryGetProperty("access_token", out _).Should().BeTrue(
            "dynamically registered client should receive an access_token");
        tokenJson.GetProperty("token_type").GetString().Should().Be("Bearer");
    }

    [Fact]
    public async Task Register_WithRefreshAndAuthCode_HasCorrectPermissions()
    {
        var req = DynRegRequest(new
        {
            redirect_uris = new[] { "http://localhost/callback" },
            grant_types = new[] { "authorization_code", "refresh_token" },
            response_types = new[] { "code" },
            scope = "openid profile email",
            client_name = "E2E Full OIDC"
        });

        var resp = await _http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.Created);

        var json = await ParseJson(resp);
        json.GetProperty("client_id").GetString().Should().NotBeNullOrWhiteSpace();
        json.GetProperty("client_secret").GetString().Should().NotBeNullOrWhiteSpace();

        var grantTypes = json.GetProperty("grant_types");
        grantTypes.GetArrayLength().Should().Be(2);
    }

    // ══════════════════════════════════════════════
    //  Initial access token enforcement
    // ══════════════════════════════════════════════

    [Fact]
    public async Task Register_WithoutAccessToken_Returns401()
    {
        // No Bearer token → should be rejected
        var req = new HttpRequestMessage(HttpMethod.Post, "/connect/register")
        {
            Content = JsonContent.Create(new
            {
                redirect_uris = new[] { "http://localhost/callback" },
                client_name = "No Token"
            })
        };

        var resp = await _http.SendAsync(req);

        resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        var json = await ParseJson(resp);
        json.GetProperty("error").GetString().Should().Be("invalid_token");
    }

    [Fact]
    public async Task Register_WithWrongAccessToken_Returns401()
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/connect/register")
        {
            Content = JsonContent.Create(new
            {
                redirect_uris = new[] { "http://localhost/callback" },
                client_name = "Wrong Token"
            })
        };
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "completely-wrong-token");

        var resp = await _http.SendAsync(req);

        resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        var json = await ParseJson(resp);
        json.GetProperty("error").GetString().Should().Be("invalid_token");
    }

    // ══════════════════════════════════════════════
    //  Validation errors
    // ══════════════════════════════════════════════

    [Fact]
    public async Task Register_InvalidGrantType_Returns400()
    {
        var req = DynRegRequest(new
        {
            redirect_uris = new[] { "http://localhost/callback" },
            grant_types = new[] { "urn:ietf:params:oauth:grant-type:device_code" }, // not in allowed list
            client_name = "Bad Grant"
        });

        var resp = await _http.SendAsync(req);

        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var json = await ParseJson(resp);
        json.GetProperty("error").GetString().Should().Be("invalid_client_metadata");
        json.GetProperty("error_description").GetString().Should().Contain("not allowed");
    }

    [Fact]
    public async Task Register_DisallowedScope_Returns400()
    {
        var req = DynRegRequest(new
        {
            redirect_uris = new[] { "http://localhost/callback" },
            scope = "openid identity:manage", // identity:manage is forbidden
            client_name = "Scope Escalation"
        });

        var resp = await _http.SendAsync(req);

        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var json = await ParseJson(resp);
        json.GetProperty("error").GetString().Should().Be("invalid_client_metadata");
        json.GetProperty("error_description").GetString().Should().Contain("not allowed");
    }

    [Fact]
    public async Task Register_MissingRedirectUris_Returns400()
    {
        // authorization_code requires redirect_uris
        var req = DynRegRequest(new
        {
            grant_types = new[] { "authorization_code" },
            client_name = "No URIs"
        });

        var resp = await _http.SendAsync(req);

        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var json = await ParseJson(resp);
        json.GetProperty("error").GetString().Should().Be("invalid_redirect_uri");
    }

    [Fact]
    public async Task Register_InvalidBody_Returns400()
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/connect/register")
        {
            Content = new StringContent("not json at all", System.Text.Encoding.UTF8, "application/json")
        };
        req.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", ProductionHttpFixture.DynamicRegAccessToken);

        var resp = await _http.SendAsync(req);

        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var json = await ParseJson(resp);
        json.GetProperty("error").GetString().Should().Be("invalid_client_metadata");
    }

    [Fact]
    public async Task Register_UnsupportedAuthMethod_Returns400()
    {
        // RFC 7591 §2 token_endpoint_auth_method values we currently support:
        //   none, client_secret_basic, client_secret_post, private_key_jwt
        // (the test originally used "private_key_jwt" — but DynamicRegistrationProcessor now
        // accepts it as a confidential client and routes through the jwks-required branch,
        // so a request with that method + no jwks yields a SPECIFIC
        // "private_key_jwt requires `jwks`" error rather than the generic Unsupported one
        // the test name asks for.) `client_secret_jwt` is RFC 7523 §2.2 but our processor
        // doesn't implement it, so it correctly falls into the Unsupported else-branch.
        var req = DynRegRequest(new
        {
            redirect_uris = new[] { "http://localhost/callback" },
            token_endpoint_auth_method = "client_secret_jwt",
            client_name = "Bad Auth Method"
        });

        var resp = await _http.SendAsync(req);

        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var json = await ParseJson(resp);
        json.GetProperty("error").GetString().Should().Be("invalid_client_metadata");
        json.GetProperty("error_description").GetString().Should().Contain("Unsupported");
    }

    [Fact]
    public async Task Register_InvalidApplicationType_Returns400()
    {
        var req = DynRegRequest(new
        {
            redirect_uris = new[] { "http://localhost/callback" },
            application_type = "desktop",
            client_name = "Bad App Type"
        });

        var resp = await _http.SendAsync(req);

        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var json = await ParseJson(resp);
        json.GetProperty("error").GetString().Should().Be("invalid_client_metadata");
    }

    // ══════════════════════════════════════════════
    //  Discovery integration
    // ══════════════════════════════════════════════

    [Fact]
    public async Task Discovery_ContainsRegistrationEndpoint_WhenEnabled()
    {
        var resp = await _http.GetAsync("/.well-known/openid-configuration");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);

        var json = await ParseJson(resp);
        json.TryGetProperty("registration_endpoint", out var regEndpoint).Should().BeTrue(
            "registration_endpoint must appear in discovery when EnableDynamicRegistration=true");

        var expected = $"http://localhost:{_fx.Port}/connect/register";
        regEndpoint.GetString().Should().Be(expected);
    }

    // ══════════════════════════════════════════════
    //  Helpers
    // ══════════════════════════════════════════════

    /// <summary>
    /// Creates a POST /connect/register request with valid initial access token.
    /// </summary>
    private static HttpRequestMessage DynRegRequest(object body)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/connect/register")
        {
            Content = JsonContent.Create(body)
        };
        req.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", ProductionHttpFixture.DynamicRegAccessToken);
        return req;
    }

    private static async Task<JsonElement> ParseJson(HttpResponseMessage resp)
    {
        var body = await resp.Content.ReadAsStringAsync();
        return JsonDocument.Parse(body).RootElement;
    }
}
