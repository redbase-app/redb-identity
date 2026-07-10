using System.Net;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// C5 — redirect_uri exact-match validation (RFC 6749 §3.1.2 / OAuth 2.1 §4.1).
/// Verifies that OpenIddict performs exact (no-substring, no-wildcard) matching
/// of the redirect_uri presented at /connect/authorize against the registered set.
/// </summary>
[Collection("ProductionHttp")]
public sealed class RedirectUriValidationTests
{
    private readonly ProductionHttpFixture _fx;

    public RedirectUriValidationTests(ProductionHttpFixture fx) => _fx = fx;

    [Fact]
    public async Task AuthorizeWithUnregisteredRedirectUri_IsRejected()
    {
        var (_, challenge) = GeneratePkce();

        var resp = await PostAuthorizeAsync(new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionHttpFixture.TestPublicClientId,
            // Registered URI is "http://localhost/callback"; this is an attacker URI.
            ["redirect_uri"] = "https://evil.example.com/callback",
            ["scope"] = "openid",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
        });

        await AssertRejectedAsync(resp, "redirect_uri",
            "unregistered redirect_uri must be rejected (no open redirect)");
    }

    [Fact]
    public async Task AuthorizeWithRedirectUriExtraQueryParam_IsRejected()
    {
        // Exact match: registered URI has no query string. Adding `?evil=1` must
        // make matching fail, otherwise an attacker could smuggle parameters.
        var (_, challenge) = GeneratePkce();

        var resp = await PostAuthorizeAsync(new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionHttpFixture.TestPublicClientId,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri + "?evil=1",
            ["scope"] = "openid",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
        });

        await AssertRejectedAsync(resp, "redirect_uri",
            "redirect_uri with extra query parameter must not match registered URI");
    }

    // ─────────────── helpers ───────────────

    private async Task<HttpResponseMessage> PostAuthorizeAsync(IDictionary<string, string> form)
    {
        var cookieJar = new CookieContainer();
        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            CookieContainer = cookieJar,
            UseCookies = true,
        };
        using var client = new HttpClient(handler) { BaseAddress = new Uri(_fx.BaseUrl) };

        await client.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = ProductionHttpFixture.TestUsername,
            ["password"] = ProductionHttpFixture.TestPassword,
        }));

        return await client.PostAsync("/connect/authorize", new FormUrlEncodedContent(form));
    }

    private static async Task AssertRejectedAsync(HttpResponseMessage resp, string parameterName, string because)
    {
        // Critical: the server MUST NOT redirect the browser to the unregistered URI.
        // It either returns a 4xx with `error=invalid_request` (or similar) JSON,
        // or shows an error page — but never `Location: <unregistered>`.
        if (resp.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found or HttpStatusCode.SeeOther)
        {
            var location = resp.Headers.Location?.ToString() ?? "";
            location.Should().NotContain("evil.example.com",
                "browser must NOT be redirected to an unregistered URI ({0})", because);
            location.Should().NotContain("evil=1",
                "browser must NOT be redirected with attacker-controlled extras ({0})", because);
            return;
        }

        resp.IsSuccessStatusCode.Should().BeFalse(
            because + $". Got {resp.StatusCode}");

        var body = await resp.Content.ReadAsStringAsync();
        if (body.Length > 0 && body.TrimStart().StartsWith('{'))
        {
            var json = JsonDocument.Parse(body).RootElement;
            if (json.TryGetProperty("error", out var err))
            {
                var errStr = err.GetString();
                errStr.Should().BeOneOf(new[] { "invalid_request", "invalid_client", "unauthorized_client" },
                    because + $". Body: {body}");
            }
        }
    }

    private static (string verifier, string challenge) GeneratePkce()
    {
        var bytes = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        var verifier = Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var hash = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(verifier));
        var challenge = Convert.ToBase64String(hash).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return (verifier, challenge);
    }
}
