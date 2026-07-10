using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// Full-cycle E2E test for Pushed Authorization Requests (RFC 9126 / Z6).
/// Pipeline: POST /connect/par → GET /connect/authorize?request_uri=… →
/// (login + implicit consent) → callback → POST /connect/token → access_token.
/// Validates that PAR-issued <c>request_uri</c> is single-use and short-lived per RFC.
/// </summary>
[Collection("ProductionHttp")]
public class PushedAuthorizationFullCycleTests
{
    private readonly ProductionHttpFixture _fx;

    public PushedAuthorizationFullCycleTests(ProductionHttpFixture fx)
    {
        _fx = fx;
    }

    [Fact]
    public async Task ParEndpoint_AdvertisedInDiscovery()
    {
        var resp = await _fx.Http.GetAsync("/.well-known/openid-configuration");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var json = await ParseJson(resp);

        json.TryGetProperty("pushed_authorization_request_endpoint", out var parEndpoint)
            .Should().BeTrue("PAR endpoint must be advertised when EnablePushedAuthorization=true");
        parEndpoint.GetString().Should().EndWith("/connect/par");
    }

    [Fact]
    public async Task Par_RejectsRequestWithoutPkce_ForPublicClient()
    {
        var parForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionHttpFixture.TestPublicClientId,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
            ["scope"] = "openid"
            // intentionally no code_challenge
        });
        var resp = await _fx.Http.PostAsync("/connect/par", parForm);

        ((int)resp.StatusCode).Should().BeGreaterOrEqualTo(400,
            "PAR for a PKCE-required public client without code_challenge must fail");
        var json = await ParseJson(resp);
        json.TryGetProperty("error", out _).Should().BeTrue();
    }

    [Fact]
    public async Task Par_FullCycle_ReturnsRequestUri_And_Authorize_With_RequestUri_Yields_Code_And_Token()
    {
        var (verifier, challenge) = GeneratePkce();

        // ─── Step 1: POST /connect/par — push the authorization parameters ───
        var parForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionHttpFixture.TestPublicClientId,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
            ["scope"] = "openid",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["state"] = "par-e2e-state",
            ["nonce"] = "par-e2e-nonce"
        });
        var parResp = await _fx.Http.PostAsync("/connect/par", parForm);
        parResp.StatusCode.Should().Be(HttpStatusCode.Created,
            "RFC 9126 §2.2 requires 201 Created for a successful PAR response: {0}",
            await parResp.Content.ReadAsStringAsync());

        var parJson = await ParseJson(parResp);
        parJson.TryGetProperty("request_uri", out var requestUriProp).Should().BeTrue();
        var requestUri = requestUriProp.GetString();
        requestUri.Should().NotBeNullOrEmpty();
        requestUri!.Should().StartWith("urn:ietf:params:oauth:request_uri:",
            "RFC 9126 §2.2: request_uri MUST use the urn:ietf:params:oauth:request_uri prefix");

        parJson.TryGetProperty("expires_in", out var expProp).Should().BeTrue();
        expProp.GetInt32().Should().BePositive();

        // ─── Step 2: Login (cookie-based session) ───
        var cookies = new CookieContainer();
        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            CookieContainer = cookies,
            UseCookies = true
        };
        using var browser = new HttpClient(handler) { BaseAddress = new Uri(_fx.BaseUrl) };

        var loginForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = ProductionHttpFixture.TestUsername,
            ["password"] = ProductionHttpFixture.TestPassword
        });
        await browser.PostAsync("/login", loginForm);
        cookies.Count.Should().BeGreaterThan(0, "login must set a session cookie");

        // ─── Step 3: GET /connect/authorize?client_id=…&request_uri=… ───
        // Per RFC 9126 §4: only client_id + request_uri are required at /authorize;
        // all other params come from the pushed payload.
        var authorizeUrl = $"/connect/authorize?client_id={Uri.EscapeDataString(ProductionHttpFixture.TestPublicClientId)}" +
                           $"&request_uri={Uri.EscapeDataString(requestUri)}";
        var authResp = await browser.GetAsync(authorizeUrl);

        string? code;
        if (authResp.StatusCode == HttpStatusCode.Redirect ||
            authResp.StatusCode == HttpStatusCode.Found)
        {
            var location = authResp.Headers.Location?.ToString();
            location.Should().NotBeNullOrEmpty("authorize must redirect to redirect_uri");
            location!.Should().StartWith(ProductionHttpFixture.TestRedirectUri);
            code = ExtractQueryParam(location, "code");
            ExtractQueryParam(location, "state").Should().Be("par-e2e-state",
                "state from PAR payload must be echoed back to the client");
        }
        else
        {
            authResp.StatusCode.Should().Be(HttpStatusCode.OK,
                "authorize response: {0}", await authResp.Content.ReadAsStringAsync());
            var json = await ParseJson(authResp);
            json.TryGetProperty("code", out var c).Should().BeTrue();
            code = c.GetString();
        }

        code.Should().NotBeNullOrEmpty("authorize must produce an authorization code");

        // ─── Step 4: POST /connect/token — exchange code with code_verifier ───
        var tokenForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code!,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
            ["client_id"] = ProductionHttpFixture.TestPublicClientId,
            ["code_verifier"] = verifier
        });
        var tokenResp = await _fx.Http.PostAsync("/connect/token", tokenForm);
        tokenResp.StatusCode.Should().Be(HttpStatusCode.OK,
            "token exchange after PAR must succeed: {0}",
            await tokenResp.Content.ReadAsStringAsync());

        var tokenJson = await ParseJson(tokenResp);
        tokenJson.TryGetProperty("access_token", out var at).Should().BeTrue();
        at.GetString().Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task Par_RequestUri_IsSingleUse()
    {
        var (_, challenge) = GeneratePkce();

        var parForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionHttpFixture.TestPublicClientId,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
            ["scope"] = "openid",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["state"] = "single-use-state"
        });
        var parResp = await _fx.Http.PostAsync("/connect/par", parForm);
        parResp.StatusCode.Should().Be(HttpStatusCode.Created);
        var requestUri = (await ParseJson(parResp)).GetProperty("request_uri").GetString()!;

        // Login + first authorize consumes the request_uri
        var cookies = new CookieContainer();
        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            CookieContainer = cookies,
            UseCookies = true
        };
        using var browser = new HttpClient(handler) { BaseAddress = new Uri(_fx.BaseUrl) };
        await browser.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = ProductionHttpFixture.TestUsername,
            ["password"] = ProductionHttpFixture.TestPassword
        }));

        var url = $"/connect/authorize?client_id={Uri.EscapeDataString(ProductionHttpFixture.TestPublicClientId)}" +
                  $"&request_uri={Uri.EscapeDataString(requestUri)}";
        var first = await browser.GetAsync(url);
        ((int)first.StatusCode).Should().BeLessThan(500,
            "first /authorize call should not 500: {0}", await first.Content.ReadAsStringAsync());

        // Second use of the same request_uri MUST fail (RFC 9126 §6 — single-use)
        var second = await browser.GetAsync(url);
        if (second.StatusCode == HttpStatusCode.Redirect || second.StatusCode == HttpStatusCode.Found)
        {
            var loc = second.Headers.Location?.ToString() ?? "";
            // Either redirected to /login (session-related) or back to redirect_uri with error
            (loc.Contains("error=") || loc.StartsWith("/login"))
                .Should().BeTrue("replayed request_uri must not produce a fresh code, got: {0}", loc);
        }
        else
        {
            ((int)second.StatusCode).Should().BeGreaterOrEqualTo(400,
                "replayed request_uri must be rejected, got status {0}: {1}",
                second.StatusCode, await second.Content.ReadAsStringAsync());
        }
    }

    // ─── Helpers ───

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
        // Strip fragment if present (response_mode=fragment)
        var hashIdx = query.IndexOf('#');
        if (hashIdx >= 0) query = query[..hashIdx];
        foreach (var pair in query.Split('&'))
        {
            var kv = pair.Split('=', 2);
            if (kv.Length == 2 && kv[0] == param)
                return Uri.UnescapeDataString(kv[1]);
        }
        // Try fragment
        var fragIdx = url.IndexOf('#');
        if (fragIdx >= 0)
        {
            foreach (var pair in url[(fragIdx + 1)..].Split('&'))
            {
                var kv = pair.Split('=', 2);
                if (kv.Length == 2 && kv[0] == param)
                    return Uri.UnescapeDataString(kv[1]);
            }
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
