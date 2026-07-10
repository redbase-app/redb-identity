using System.Net;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.OAuth;

/// <summary>
/// G8 — supplemental OAuth/OIDC validation tests beyond what is covered by
/// <c>PkceEnforcementTests</c> and <c>RedirectUriValidationTests</c>.
/// <list type="bullet">
///   <item>OIDC §3.2.2.1: <c>response_type=id_token</c> requires the <c>openid</c>
///         scope; without it the request is malformed.</item>
///   <item>RFC 6749 §3.3: scope values are space-delimited; comma-separated scopes
///         are NOT a valid scope list — they yield a single bogus scope token.</item>
/// </list>
/// </summary>
[Collection("ProductionHttp")]
public sealed class ScopeAndResponseTypeTests
{
    private readonly ProductionHttpFixture _fx;

    public ScopeAndResponseTypeTests(ProductionHttpFixture fx) => _fx = fx;

    [Fact]
    public async Task IdTokenResponseType_WithoutOpenidScope_IsRejected()
    {
        // OpenID Connect Core §3.2.2.1: when response_type contains id_token, scope
        // MUST contain "openid" — otherwise the server cannot determine the subject
        // for the implicit ID token.
        var (_, challenge) = GeneratePkce();

        var resp = await PostAuthorizeAsync(new Dictionary<string, string>
        {
            ["response_type"] = "id_token",
            ["client_id"] = ProductionHttpFixture.TestPublicClientId,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
            ["scope"] = "profile",   // intentionally missing "openid"
            ["nonce"] = "n-" + Guid.NewGuid().ToString("N"),
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
        });

        await AssertOAuthErrorAsync(resp,
            "id_token response_type without 'openid' scope must be rejected (OIDC §3.2.2.1)");
    }

    [Fact]
    public async Task CommaDelimitedScopes_AreNotParsedAsMultipleScopes()
    {
        // RFC 6749 §3.3: scope = scope-token *( SP scope-token ). Comma is NOT a
        // valid delimiter — "openid,profile" is a single (and unregistered) scope
        // token, so the server must either reject as invalid_scope or treat it as
        // an unknown scope. It MUST NOT silently grant both "openid" AND "profile".
        var (_, challenge) = GeneratePkce();

        var resp = await PostAuthorizeAsync(new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionHttpFixture.TestPublicClientId,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
            ["scope"] = "openid,profile",  // RFC violation — must NOT be split on comma
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
        });

        // Acceptable outcomes per RFC 6749 §4.1.2.1:
        //   (a) error=invalid_scope (server recognised the bogus token and refused);
        //   (b) success but the resulting authorization MUST NOT include a "profile"
        //       scope grant — comma split would be a security regression.
        if (resp.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found)
        {
            var location = resp.Headers.Location?.ToString() ?? "";
            // If redirected back with a code, the only granted scope can be "openid,profile"
            // as a single token (which is unregistered), or nothing — never the split set.
            location.Should().NotContain("scope=openid+profile",
                "comma-delimited scope must NOT be silently split into space-delimited grant");
            location.Should().NotContain("scope=openid%20profile",
                "comma-delimited scope must NOT be silently split into space-delimited grant");
        }
        else
        {
            // Direct error response — must be invalid_scope or invalid_request, never 200.
            resp.IsSuccessStatusCode.Should().BeFalse(
                "comma-delimited scope must be rejected as malformed");
        }
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

    private static async Task AssertOAuthErrorAsync(HttpResponseMessage resp, string because)
    {
        if (resp.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found)
        {
            var location = resp.Headers.Location?.ToString() ?? "";
            location.Should().MatchRegex(@"error=(invalid_request|invalid_scope|unsupported_response_type)",
                because);
            return;
        }

        resp.IsSuccessStatusCode.Should().BeFalse(because + $". Got {resp.StatusCode}");

        var body = await resp.Content.ReadAsStringAsync();
        if (body.Length > 0 && body.TrimStart().StartsWith('{'))
        {
            var json = JsonDocument.Parse(body).RootElement;
            if (json.TryGetProperty("error", out var err))
            {
                err.GetString().Should().BeOneOf(
                    "invalid_request", "invalid_scope", "unsupported_response_type");
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
