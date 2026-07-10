using System.Net;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// C4 — PKCE enforcement (OAuth 2.1 / RFC 7636 §4.2):
///   1. authorize without code_challenge from a public client → invalid_request
///   2. authorize with code_challenge_method=plain → invalid_request
///   3. authorize with code_challenge_method=S256 → success (control case)
/// Public clients (no client_secret) are required to use PKCE; only S256 is accepted.
/// </summary>
[Collection("ProductionHttp")]
public sealed class PkceEnforcementTests
{
    private readonly ProductionHttpFixture _fx;

    public PkceEnforcementTests(ProductionHttpFixture fx) => _fx = fx;

    [Fact]
    public async Task PublicClient_AuthorizeWithoutCodeChallenge_ReturnsInvalidRequest()
    {
        var resp = await PostAuthorizeAsync(new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionHttpFixture.TestPublicClientId,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
            ["scope"] = "openid",
            // intentionally no code_challenge / code_challenge_method
        });

        await AssertInvalidRequestAsync(resp,
            "public client authorize without PKCE must be rejected");
    }

    [Fact]
    public async Task AuthorizeWithPlainCodeChallengeMethod_IsRejected()
    {
        var (_, challenge) = GeneratePkce();

        var resp = await PostAuthorizeAsync(new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionHttpFixture.TestPublicClientId,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
            ["scope"] = "openid",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "plain",
        });

        await AssertInvalidRequestAsync(resp,
            "code_challenge_method=plain must be rejected (OAuth 2.1)");
    }

    [Fact]
    public async Task AuthorizeWithSha256CodeChallenge_Succeeds()
    {
        var (_, challenge) = GeneratePkce();

        var resp = await PostAuthorizeAsync(new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionHttpFixture.TestPublicClientId,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
            ["scope"] = "openid",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
        });

        // Either a 302 redirect with `?code=...` or 200 JSON containing `code` is acceptable.
        if (resp.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found)
        {
            var location = resp.Headers.Location?.ToString();
            location.Should().NotBeNullOrEmpty();
            location!.Should().Contain("code=", "authorize with S256 must produce an authorization code");
            return;
        }

        var body = await resp.Content.ReadAsStringAsync();
        resp.IsSuccessStatusCode.Should().BeTrue(
            "authorize with code_challenge_method=S256 must succeed; got {0}: {1}",
            resp.StatusCode, body);
        var json = JsonDocument.Parse(body).RootElement;
        json.TryGetProperty("code", out var code).Should().BeTrue("response must contain a code");
        code.GetString().Should().NotBeNullOrEmpty();
    }

    // ─────────────── helpers ───────────────

    private async Task<HttpResponseMessage> PostAuthorizeAsync(IDictionary<string, string> form)
    {
        // Authenticate first to get a session cookie, otherwise OpenIddict will
        // bounce us to /login (which would mask the actual PKCE rejection).
        var cookieJar = new System.Net.CookieContainer();
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

    private static async Task AssertInvalidRequestAsync(HttpResponseMessage resp, string because)
    {
        // OpenIddict can either return a 302 with error=invalid_request in the redirect
        // (when redirect_uri is registered) or a JSON 400. Accept both.
        if (resp.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found)
        {
            var location = resp.Headers.Location?.ToString() ?? "";
            location.Should().Contain("error=invalid_request", because);
            return;
        }

        resp.IsSuccessStatusCode.Should().BeFalse(because + $". Got {resp.StatusCode}");
        var body = await resp.Content.ReadAsStringAsync();
        if (body.Length > 0 && body.TrimStart().StartsWith('{'))
        {
            var json = JsonDocument.Parse(body).RootElement;
            if (json.TryGetProperty("error", out var err))
            {
                err.GetString().Should().Be("invalid_request", because + $". Body: {body}");
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
