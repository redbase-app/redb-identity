using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// Full-stack E2E tests for OIDC protocol endpoints.
/// Complete path: HTTP request → Kestrel → HTTP facade → direct-vm:// → OpenIddict pipeline
/// → redb stores → PostgreSQL → response → HTTP.
/// Uses PRODUCTION OpenIddict (real stores, no degraded mode).
/// </summary>
[Collection("ProductionHttp")]
public class FullStackProtocolTests
{
    private readonly ProductionHttpFixture _fx;
    private readonly HttpClient _http;

    public FullStackProtocolTests(ProductionHttpFixture fx)
    {
        _fx = fx;
        _http = fx.Http;
    }

    // ══════════════════════════════════════════════
    //  Client Credentials
    // ══════════════════════════════════════════════

    [Fact]
    public async Task ClientCredentials_ViaHttp_ReturnsJwt()
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = ProductionHttpFixture.TestClientId,
            ["client_secret"] = ProductionHttpFixture.TestClientSecret
        });

        var resp = await _http.PostAsync("/connect/token", content);

        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            "token request failed: {0}", await resp.Content.ReadAsStringAsync());
        var json = await ParseJson(resp);
        json.TryGetProperty("access_token", out var at).Should().BeTrue();

        var jwt = at.GetString()!;
        jwt.Split('.').Should().HaveCount(3, "access_token should be a JWT");
        json.GetProperty("token_type").GetString().Should().Be("Bearer");
    }

    [Fact]
    public async Task ClientCredentials_JwtContainsCorrectIssuer()
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = ProductionHttpFixture.TestClientId,
            ["client_secret"] = ProductionHttpFixture.TestClientSecret,
            ["scope"] = "openid"
        });

        var resp = await _http.PostAsync("/connect/token", content);
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var json = await ParseJson(resp);
        var jwt = json.GetProperty("access_token").GetString()!;

        var payload = DecodeJwtPayload(jwt);
        payload.GetProperty("iss").GetString().Should().Be($"http://localhost:{_fx.Port}/");
    }

    [Fact]
    public async Task ClientCredentials_InvalidSecret_ReturnsError()
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = ProductionHttpFixture.TestClientId,
            ["client_secret"] = "wrong-secret"
        });

        var resp = await _http.PostAsync("/connect/token", content);
        resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        var json = await ParseJson(resp);
        json.GetProperty("error").GetString().Should().Be("invalid_client");
    }

    // ══════════════════════════════════════════════
    //  Authorization Code + PKCE
    // ══════════════════════════════════════════════

    [Fact]
    public async Task AuthCode_PKCE_FullExchange_ViaHttp()
    {
        var (verifier, challenge) = GeneratePkce();

        // Step 1: Authorize → get code
        var code = await AuthorizeViaHttp(
            ProductionHttpFixture.TestPublicClientId, challenge, "openid offline_access");
        code.Should().NotBeNullOrEmpty("authorize should return a code");

        // Step 2: Exchange code → tokens
        var tokenContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
            ["client_id"] = ProductionHttpFixture.TestPublicClientId,
            ["code_verifier"] = verifier
        });

        var tokenResp = await _http.PostAsync("/connect/token", tokenContent);
        tokenResp.StatusCode.Should().Be(HttpStatusCode.OK,
            "token exchange failed: {0}", await tokenResp.Content.ReadAsStringAsync());
        var json = await ParseJson(tokenResp);

        json.TryGetProperty("access_token", out _).Should().BeTrue();
        json.GetProperty("token_type").GetString().Should().Be("Bearer");
        json.TryGetProperty("refresh_token", out _).Should().BeTrue(
            "offline_access scope should yield a refresh_token");
    }

    [Fact]
    public async Task AuthCode_ConfidentialClient_FullExchange_ViaHttp()
    {
        var (verifier, challenge) = GeneratePkce();

        var code = await AuthorizeViaHttp(
            ProductionHttpFixture.TestClientId, challenge, "openid",
            ProductionHttpFixture.TestClientSecret);
        code.Should().NotBeNullOrEmpty();

        var tokenContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
            ["client_id"] = ProductionHttpFixture.TestClientId,
            ["client_secret"] = ProductionHttpFixture.TestClientSecret,
            ["code_verifier"] = verifier
        });

        var tokenResp = await _http.PostAsync("/connect/token", tokenContent);
        tokenResp.StatusCode.Should().Be(HttpStatusCode.OK,
            "token exchange failed: {0}", await tokenResp.Content.ReadAsStringAsync());
        var json = await ParseJson(tokenResp);
        json.TryGetProperty("access_token", out _).Should().BeTrue();
    }

    // ══════════════════════════════════════════════
    //  Refresh Token Rotation
    // ══════════════════════════════════════════════

    [Fact]
    public async Task RefreshToken_Rotation_ViaHttp()
    {
        // Get initial tokens via auth code flow
        var (verifier, challenge) = GeneratePkce();
        var code = await AuthorizeViaHttp(
            ProductionHttpFixture.TestPublicClientId, challenge, "openid offline_access");

        var exchangeContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code!,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
            ["client_id"] = ProductionHttpFixture.TestPublicClientId,
            ["code_verifier"] = verifier
        });
        var exchangeResp = await _http.PostAsync("/connect/token", exchangeContent);
        var initial = await ParseJson(exchangeResp);
        var refreshToken = initial.GetProperty("refresh_token").GetString()!;

        // Rotate: use refresh_token to get new tokens
        var refreshContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
            ["client_id"] = ProductionHttpFixture.TestPublicClientId
        });
        var refreshResp = await _http.PostAsync("/connect/token", refreshContent);
        refreshResp.StatusCode.Should().Be(HttpStatusCode.OK,
            "refresh failed: {0}", await refreshResp.Content.ReadAsStringAsync());
        var rotated = await ParseJson(refreshResp);

        rotated.TryGetProperty("access_token", out _).Should().BeTrue();
        rotated.TryGetProperty("refresh_token", out var newRt).Should().BeTrue();
        newRt.GetString().Should().NotBe(refreshToken, "rotation should produce a new refresh token");
    }

    // ══════════════════════════════════════════════
    //  Introspection (RFC 7662)
    // ══════════════════════════════════════════════

    [Fact]
    public async Task Introspect_ValidToken_ReturnsActive()
    {
        var token = await ObtainAccessToken();

        var resp = await _http.PostAsync("/connect/introspect", IntrospectBody(token));

        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var json = await ParseJson(resp);
        json.GetProperty("active").GetBoolean().Should().BeTrue(
            "freshly issued token must be active via production store lookup");
    }

    // ══════════════════════════════════════════════
    //  Revocation → Introspection lifecycle (THE KEY TEST)
    // ══════════════════════════════════════════════

    [Fact]
    public async Task Revoke_ThenIntrospect_ReturnsInactive()
    {
        // 1. Issue token (persisted in PostgreSQL via RedbTokenStore)
        var token = await ObtainAccessToken();

        // 2. Verify active
        var resp1 = await _http.PostAsync("/connect/introspect", IntrospectBody(token));
        resp1.StatusCode.Should().Be(HttpStatusCode.OK);
        var json1 = await ParseJson(resp1);
        json1.GetProperty("active").GetBoolean().Should().BeTrue(
            "token should be active before revocation");

        // 3. Revoke (updates status in PostgreSQL)
        var revokeResp = await _http.PostAsync("/connect/revocation", RevokeBody(token));
        revokeResp.StatusCode.Should().Be(HttpStatusCode.OK);

        // 4. Introspect again — token must NOT be active anymore
        //    OpenIddict may return 200 {active:false} or reject with 401 for revoked tokens
        var resp2 = await _http.PostAsync("/connect/introspect", IntrospectBody(token));
        var tokenStillActive = false;
        if (resp2.StatusCode == HttpStatusCode.OK)
        {
            var json2 = await ParseJson(resp2);
            if (json2.TryGetProperty("active", out var active))
                tokenStillActive = active.GetBoolean();
        }

        tokenStillActive.Should().BeFalse(
            "revoked token must not be active — verified via production store (PostgreSQL)");
    }

    // ══════════════════════════════════════════════
    //  Userinfo
    // ══════════════════════════════════════════════

    [Fact]
    public async Task Userinfo_ViaHttp_ReturnsProfileClaims()
    {
        // Get access token with profile scope via auth code flow
        var (verifier, challenge) = GeneratePkce();
        var code = await AuthorizeViaHttp(
            ProductionHttpFixture.TestClientId, challenge, "openid profile email",
            ProductionHttpFixture.TestClientSecret);

        var tokenContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code!,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
            ["client_id"] = ProductionHttpFixture.TestClientId,
            ["client_secret"] = ProductionHttpFixture.TestClientSecret,
            ["code_verifier"] = verifier
        });
        var tokenResp = await _http.PostAsync("/connect/token", tokenContent);
        var tokenJson = await ParseJson(tokenResp);
        var accessToken = tokenJson.GetProperty("access_token").GetString()!;

        // Call userinfo with bearer token
        var req = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var userinfoResp = await _http.SendAsync(req);

        userinfoResp.StatusCode.Should().Be(HttpStatusCode.OK,
            "userinfo failed: {0}", await userinfoResp.Content.ReadAsStringAsync());
        var userinfo = await ParseJson(userinfoResp);

        userinfo.TryGetProperty("sub", out _).Should().BeTrue("userinfo must contain sub");
        userinfo.TryGetProperty("given_name", out var gn).Should().BeTrue();
        gn.GetString().Should().Be("E2E");
        userinfo.TryGetProperty("family_name", out var fn).Should().BeTrue();
        fn.GetString().Should().Be("Tester");
        userinfo.TryGetProperty("email", out var em).Should().BeTrue();
        em.GetString().Should().Be("e2e@example.com");
    }

    [Fact]
    public async Task Userinfo_Post_ViaHttp_ReturnsProfileClaims()
    {
        // Get access token with profile scope via auth code flow
        var (verifier, challenge) = GeneratePkce();
        var code = await AuthorizeViaHttp(
            ProductionHttpFixture.TestClientId, challenge, "openid profile email",
            ProductionHttpFixture.TestClientSecret);

        var tokenContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code!,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
            ["client_id"] = ProductionHttpFixture.TestClientId,
            ["client_secret"] = ProductionHttpFixture.TestClientSecret,
            ["code_verifier"] = verifier
        });
        var tokenResp = await _http.PostAsync("/connect/token", tokenContent);
        var tokenJson = await ParseJson(tokenResp);
        var accessToken = tokenJson.GetProperty("access_token").GetString()!;

        // Call userinfo via POST with bearer token
        var req = new HttpRequestMessage(HttpMethod.Post, "/connect/userinfo");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var userinfoResp = await _http.SendAsync(req);

        userinfoResp.StatusCode.Should().Be(HttpStatusCode.OK,
            "userinfo POST failed: {0}", await userinfoResp.Content.ReadAsStringAsync());
        var userinfo = await ParseJson(userinfoResp);

        userinfo.TryGetProperty("sub", out _).Should().BeTrue("userinfo must contain sub");
        userinfo.TryGetProperty("given_name", out var gn).Should().BeTrue();
        gn.GetString().Should().Be("E2E");
    }

    // ══════════════════════════════════════════════
    //  Discovery & JWKS
    // ══════════════════════════════════════════════

    [Fact]
    public async Task Discovery_ReturnsFullConfiguration()
    {
        var resp = await _http.GetAsync("/.well-known/openid-configuration");

        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var json = await ParseJson(resp);

        json.GetProperty("issuer").GetString().Should().Be($"http://localhost:{_fx.Port}/");
        json.TryGetProperty("token_endpoint", out _).Should().BeTrue();
        json.TryGetProperty("authorization_endpoint", out _).Should().BeTrue();
        json.TryGetProperty("userinfo_endpoint", out _).Should().BeTrue();
        json.TryGetProperty("introspection_endpoint", out _).Should().BeTrue();
        json.TryGetProperty("revocation_endpoint", out _).Should().BeTrue();
        json.TryGetProperty("jwks_uri", out _).Should().BeTrue();
        json.TryGetProperty("grant_types_supported", out _).Should().BeTrue();
    }

    [Fact]
    public async Task Jwks_ReturnsSigningKeys()
    {
        var resp = await _http.GetAsync("/.well-known/jwks");

        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var json = await ParseJson(resp);

        json.TryGetProperty("keys", out var keys).Should().BeTrue();
        keys.ValueKind.Should().Be(JsonValueKind.Array);
        keys.GetArrayLength().Should().BeGreaterThan(0);
    }

    // ══════════════════════════════════════════════
    //  Helpers
    // ══════════════════════════════════════════════

    private async Task<string> ObtainAccessToken()
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = ProductionHttpFixture.TestClientId,
            ["client_secret"] = ProductionHttpFixture.TestClientSecret
        });

        var resp = await _http.PostAsync("/connect/token", content);
        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            "token request failed: {0}", await resp.Content.ReadAsStringAsync());
        var json = await ParseJson(resp);
        return json.GetProperty("access_token").GetString()!;
    }

    /// <summary>
    /// Performs authorization via HTTP POST, handling both redirect (302) and JSON responses.
    /// First logs in via POST /login to obtain a session cookie, then uses it for authorize.
    /// Returns the authorization code.
    /// </summary>
    private async Task<string?> AuthorizeViaHttp(
        string clientId, string codeChallenge, string scope, string? clientSecret = null)
    {
        var cookieContainer = new System.Net.CookieContainer();
        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            CookieContainer = cookieContainer,
            UseCookies = true
        };
        using var client = new HttpClient(handler) { BaseAddress = new Uri(_fx.BaseUrl) };

        // Step 1: Login to obtain session cookie
        var loginForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = ProductionHttpFixture.TestUsername,
            ["password"] = ProductionHttpFixture.TestPassword
        });
        var loginResp = await client.PostAsync("/login", loginForm);
        // Login should set a session cookie (response may be 302 or 200)
        cookieContainer.Count.Should().BeGreaterThan(0,
            "login response must set a session cookie");

        // Step 2: Authorize with the session cookie
        var form = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = clientId,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
            ["scope"] = scope,
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256"
        };
        if (clientSecret is not null)
            form["client_secret"] = clientSecret;

        var resp = await client.PostAsync("/connect/authorize", new FormUrlEncodedContent(form));

        // The authorize endpoint may return a 302 redirect or a JSON response
        if (resp.StatusCode == HttpStatusCode.Redirect ||
            resp.StatusCode == HttpStatusCode.Found)
        {
            var location = resp.Headers.Location?.ToString();
            location.Should().NotBeNull("redirect should have a Location header");
            return ExtractQueryParam(location!, "code");
        }

        // Try JSON response (API-first flow returns code in body)
        var json = await ParseJson(resp);
        if (json.TryGetProperty("code", out var code))
            return code.GetString();

        // Propagate error info for diagnostics
        if (json.TryGetProperty("error", out var err))
            throw new InvalidOperationException(
                $"Authorize returned error: {err.GetString()} — {(json.TryGetProperty("error_description", out var d) ? d.GetString() : "no description")}");

        throw new InvalidOperationException(
            $"Unexpected authorize response ({resp.StatusCode}): {json.GetRawText()}");
    }

    private FormUrlEncodedContent IntrospectBody(string token) => new(new Dictionary<string, string>
    {
        ["token"] = token,
        ["client_id"] = ProductionHttpFixture.TestClientId,
        ["client_secret"] = ProductionHttpFixture.TestClientSecret
    });

    private FormUrlEncodedContent RevokeBody(string token) => new(new Dictionary<string, string>
    {
        ["token"] = token,
        ["client_id"] = ProductionHttpFixture.TestClientId,
        ["client_secret"] = ProductionHttpFixture.TestClientSecret
    });

    private static async Task<JsonElement> ParseJson(HttpResponseMessage resp)
    {
        var body = await resp.Content.ReadAsStringAsync();
        return JsonDocument.Parse(body).RootElement;
    }

    private static JsonElement DecodeJwtPayload(string jwt)
    {
        var parts = jwt.Split('.');
        var padded = parts[1];
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        var bytes = Convert.FromBase64String(padded.Replace('-', '+').Replace('_', '/'));
        return JsonDocument.Parse(bytes).RootElement;
    }

    private static string? ExtractQueryParam(string url, string param)
    {
        var idx = url.IndexOf('?');
        if (idx < 0) return null;
        var query = url[(idx + 1)..];
        foreach (var pair in query.Split('&'))
        {
            var kv = pair.Split('=', 2);
            if (kv[0] == param)
                return Uri.UnescapeDataString(kv[1]);
        }
        return null;
    }

    private static (string verifier, string challenge) GeneratePkce()
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
