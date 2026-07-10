using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// Full-stack E2E tests for the interactive browser-based flows:
/// login → authorize → (consent) → callback, and logout.
/// Uses real HTTP with cookie handling to simulate browser behavior.
/// </summary>
[Collection("ProductionHttp")]
public class FullStackBrowserFlowTests
{
    private readonly ProductionHttpFixture _fx;

    public FullStackBrowserFlowTests(ProductionHttpFixture fx)
    {
        _fx = fx;
    }

    // ══════════════════════════════════════════════
    //  Login page
    // ══════════════════════════════════════════════

    [Fact]
    public async Task LoginPage_Get_RendersForm()
    {
        using var client = CreateBrowserClient();
        var resp = await client.GetAsync("/login");

        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await resp.Content.ReadAsStringAsync();
        body.Should().Contain("username", "login page must have a username field");
        body.Should().Contain("password", "login page must have a password field");
        body.Should().Contain("<form", "login page must contain a form element");
    }

    [Fact]
    public async Task Login_Post_ValidCredentials_SetsCookieAndReturnsSuccess()
    {
        var cookies = new CookieContainer();
        using var client = CreateBrowserClient(cookies, allowRedirect: false);

        // POST without returnUrl → should return 200 JSON with Set-Cookie
        var loginForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = ProductionHttpFixture.TestUsername,
            ["password"] = ProductionHttpFixture.TestPassword
        });
        var resp = await client.PostAsync("/login", loginForm);

        cookies.Count.Should().BeGreaterThan(0, "login must set a session cookie");
        var body = await resp.Content.ReadAsStringAsync();
        body.Should().Contain("Login successful");
    }

    [Fact]
    public async Task Login_Post_WithReturnUrl_SetsCookieAndRedirects()
    {
        var cookies = new CookieContainer();
        using var client = CreateBrowserClient(cookies, allowRedirect: false);

        var loginForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = ProductionHttpFixture.TestUsername,
            ["password"] = ProductionHttpFixture.TestPassword,
            ["returnUrl"] = "/connect/authorize"
        });
        var resp = await client.PostAsync("/login", loginForm);

        // Should redirect with Set-Cookie
        resp.StatusCode.Should().Be(HttpStatusCode.Redirect);
        resp.Headers.Location?.ToString().Should().Be("/connect/authorize");
    }

    [Fact]
    public async Task Login_Post_InvalidCredentials_ReRendersForm()
    {
        using var client = CreateBrowserClient();

        var loginForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = "wrong-user",
            ["password"] = "wrong-password"
        });
        var resp = await client.PostAsync("/login", loginForm);

        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await resp.Content.ReadAsStringAsync();
        body.Should().Contain("username", "error page should re-render the login form");
        body.Should().Contain("<form", "error page should contain the form for retry");
    }

    // ══════════════════════════════════════════════
    //  Authorize flow (implicit consent)
    // ══════════════════════════════════════════════

    [Fact]
    public async Task Authorize_Post_WithoutSession_RedirectsToLoginOrReturnsError()
    {
        var (_, challenge) = GeneratePkce();
        using var client = CreateBrowserClient(allowRedirect: false);

        var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionHttpFixture.TestPublicClientId,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
            ["scope"] = "openid",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256"
        });
        var resp = await client.PostAsync("/connect/authorize", form);

        // Without session: either 302 to /login or an error status
        if (resp.StatusCode == HttpStatusCode.Redirect)
        {
            resp.Headers.Location?.ToString().Should().StartWith("/login");
        }
        else
        {
            // OpenIddict returns login_required which maps to 400
            ((int)resp.StatusCode).Should().BeGreaterOrEqualTo(400);
        }
    }

    [Fact]
    public async Task Authorize_Post_AfterLogin_ImplicitConsent_ReturnsCode()
    {
        var (verifier, challenge) = GeneratePkce();
        var cookies = new CookieContainer();
        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            CookieContainer = cookies,
            UseCookies = true
        };
        using var client = new HttpClient(handler) { BaseAddress = new Uri(_fx.BaseUrl) };

        // Step 1: Login (same pattern as existing AuthorizeViaHttp)
        var loginForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = ProductionHttpFixture.TestUsername,
            ["password"] = ProductionHttpFixture.TestPassword
        });
        await client.PostAsync("/login", loginForm);
        cookies.Count.Should().BeGreaterThan(0, "login must set a session cookie");

        // Step 2: POST to authorize with implicit consent client
        var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionHttpFixture.TestPublicClientId,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
            ["scope"] = "openid",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256"
        });
        var resp = await client.PostAsync("/connect/authorize", form);

        // The authorize endpoint may return a 302 redirect or JSON with the code
        string? code = null;
        if (resp.StatusCode == HttpStatusCode.Redirect)
        {
            var location = resp.Headers.Location?.ToString();
            location.Should().NotBeNull();
            code = ExtractQueryParam(location!, "code");
        }
        else
        {
            resp.StatusCode.Should().Be(HttpStatusCode.OK);
            var json = await ParseJson(resp);
            json.TryGetProperty("code", out var c).Should().BeTrue("response should contain code");
            code = c.GetString();
        }

        code.Should().NotBeNullOrEmpty("authorization code must be returned");

        // Exchange code for tokens to verify it's valid
        var tokenContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code!,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
            ["client_id"] = ProductionHttpFixture.TestPublicClientId,
            ["code_verifier"] = verifier
        });
        var tokenResp = await _fx.Http.PostAsync("/connect/token", tokenContent);
        tokenResp.StatusCode.Should().Be(HttpStatusCode.OK,
            "token exchange failed: {0}", await tokenResp.Content.ReadAsStringAsync());
        var tokenJson = await ParseJson(tokenResp);
        tokenJson.TryGetProperty("access_token", out _).Should().BeTrue();
    }

    // ══════════════════════════════════════════════
    //  Explicit consent flow
    // ══════════════════════════════════════════════

    [Fact]
    public async Task Authorize_Post_ExplicitConsent_RedirectsToConsentPage()
    {
        var (_, challenge) = GeneratePkce();
        var cookies = new CookieContainer();
        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            CookieContainer = cookies,
            UseCookies = true
        };
        using var client = new HttpClient(handler) { BaseAddress = new Uri(_fx.BaseUrl) };

        // Step 1: Login
        var loginForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = ProductionHttpFixture.TestUsername,
            ["password"] = ProductionHttpFixture.TestPassword
        });
        await client.PostAsync("/login", loginForm);
        cookies.Count.Should().BeGreaterThan(0);

        // Step 2: POST to authorize with explicit-consent client
        var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionHttpFixture.TestConsentClientId,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
            ["scope"] = "openid profile",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256"
        });
        var resp = await client.PostAsync("/connect/authorize", form);

        // Should redirect to consent page or return consent_required
        if (resp.StatusCode == HttpStatusCode.Redirect)
        {
            var location = resp.Headers.Location?.ToString();
            location.Should().NotBeNull();
            location.Should().Contain("consent",
                "explicit consent client should redirect to consent page");
        }
        else
        {
            // May return consent_required error as JSON
            var json = await ParseJson(resp);
            json.TryGetProperty("error", out var err).Should().BeTrue();
            err.GetString().Should().Be("consent_required");
        }
    }

    [Fact]
    public async Task ConsentPage_Get_RendersForm()
    {
        using var client = CreateBrowserClient();

        var resp = await client.GetAsync(
            "/consent?client_id=test&app_name=TestApp&scopes=openid,profile&user_id=1&returnUrl=/connect/authorize");

        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await resp.Content.ReadAsStringAsync();
        body.Should().Contain("TestApp", "consent page should show the app name");
        body.Should().Contain("<form", "consent page should contain a form element");
    }

    // ══════════════════════════════════════════════
    //  Logout
    // ══════════════════════════════════════════════

    [Fact]
    public async Task Logout_Get_ReturnsPageOrRedirect()
    {
        using var client = CreateBrowserClient();

        var resp = await client.GetAsync("/connect/logout");

        ((int)resp.StatusCode).Should().BeOneOf(200, 302);
    }

    [Fact]
    public async Task Logout_Post_InvalidatesSession()
    {
        var cookies = new CookieContainer();
        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            CookieContainer = cookies,
            UseCookies = true
        };
        using var client = new HttpClient(handler) { BaseAddress = new Uri(_fx.BaseUrl) };

        // Step 1: Login
        var loginForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = ProductionHttpFixture.TestUsername,
            ["password"] = ProductionHttpFixture.TestPassword
        });
        await client.PostAsync("/login", loginForm);
        cookies.Count.Should().BeGreaterThan(0);

        // Step 2: Verify session is valid — authorize should succeed
        var (_, challenge) = GeneratePkce();
        var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionHttpFixture.TestPublicClientId,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
            ["scope"] = "openid",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256"
        });
        var authResp = await client.PostAsync("/connect/authorize", form);
        // Should succeed (302 redirect or 200 JSON with code)
        ((int)authResp.StatusCode).Should().BeOneOf([200, 302],
            "authorize should succeed with valid session");

        // Step 3: Logout
        await client.PostAsync("/connect/logout", new FormUrlEncodedContent([]));

        // Step 4: Authorize again — session should be invalidated
        var (_, challenge2) = GeneratePkce();
        var form2 = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionHttpFixture.TestPublicClientId,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
            ["scope"] = "openid",
            ["code_challenge"] = challenge2,
            ["code_challenge_method"] = "S256"
        });
        var resp2 = await client.PostAsync("/connect/authorize", form2);

        // After logout, should NOT get a code — either redirect to login or error
        if (resp2.StatusCode == HttpStatusCode.Redirect)
        {
            resp2.Headers.Location?.ToString().Should().StartWith("/login",
                "authorize after logout should redirect to login");
        }
        else
        {
            // login_required error (mapped to 400+)
            ((int)resp2.StatusCode).Should().BeGreaterOrEqualTo(400,
                "authorize after logout should fail");
        }
    }

    // ══════════════════════════════════════════════
    //  Helpers
    // ══════════════════════════════════════════════

    private HttpClient CreateBrowserClient(CookieContainer? cookies = null, bool allowRedirect = true)
    {
        cookies ??= new CookieContainer();
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = allowRedirect,
            CookieContainer = cookies,
            UseCookies = true
        };
        return new HttpClient(handler) { BaseAddress = new Uri(_fx.BaseUrl) };
    }

    private static async Task<JsonElement> ParseJson(HttpResponseMessage resp)
    {
        var body = await resp.Content.ReadAsStringAsync();
        return JsonDocument.Parse(body).RootElement;
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
