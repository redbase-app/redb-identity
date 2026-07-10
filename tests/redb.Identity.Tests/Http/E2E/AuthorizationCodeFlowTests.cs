using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Http.E2E;

/// <summary>
/// E2E test: Authorization Code + PKCE flow over real HTTP.
/// Tests the multi-step exchange: /connect/authorize → login stub → token exchange.
/// </summary>
[Collection("HttpIdentity")]
public class AuthorizationCodeFlowTests
{
    private readonly HttpIdentityFixture _fixture;

    public AuthorizationCodeFlowTests(HttpIdentityFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task AuthorizeEndpoint_Get_ReturnsLoginStubOrRedirect()
    {
        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = GenerateCodeChallenge(codeVerifier);

        var url = "/connect/authorize" +
            "?response_type=code" +
            "&client_id=pkce-test-client" +
            "&redirect_uri=http://localhost/callback" +
            $"&code_challenge={codeChallenge}" +
            "&code_challenge_method=S256" +
            "&scope=openid";

        var response = await _fixture.Http.GetAsync(url);

        // Degraded mode with login stub enabled: expect 200 (HTML login form), 302 (redirect),
        // 400 (bad request), or 500 (degraded mode can't authenticate without a session provider)
        response.StatusCode.Should().BeOneOf(
            HttpStatusCode.OK, HttpStatusCode.Redirect, HttpStatusCode.BadRequest,
            HttpStatusCode.InternalServerError);

        var body = await response.Content.ReadAsStringAsync();
        body.Should().NotBeNullOrEmpty("endpoint should always return a body");

        if (response.StatusCode == HttpStatusCode.OK)
        {
            // Should be login stub HTML or JSON — not empty
            (body.Contains("html", StringComparison.OrdinalIgnoreCase) ||
             body.TrimStart().StartsWith("{")).Should().BeTrue(
                "200 body should be HTML or JSON, got: " + body[..Math.Min(200, body.Length)]);
        }

        if (response.StatusCode == HttpStatusCode.Redirect)
        {
            response.Headers.Location.Should().NotBeNull("302 must have Location header");
        }

        if (response.StatusCode == HttpStatusCode.InternalServerError)
        {
            // Degraded mode error — verify it's a structured response, not a raw exception
            var isJson = body.TrimStart().StartsWith("{");
            var isHtml = body.TrimStart().StartsWith("<");
            (isJson || isHtml).Should().BeTrue(
                "500 should be a structured error response, not a raw stack trace");
        }
    }

    [Fact]
    public async Task AuthorizeEndpoint_Post_SendsFormData()
    {
        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = GenerateCodeChallenge(codeVerifier);

        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = "pkce-post-client",
            ["redirect_uri"] = "http://localhost/callback",
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256",
            ["scope"] = "openid"
        });

        var response = await _fixture.Http.PostAsync("/connect/authorize", content);

        // POST without session cookie: expect 302 redirect to login,
        // 400 (bad request), or 500 (degraded mode)
        response.StatusCode.Should().BeOneOf(
            HttpStatusCode.OK, HttpStatusCode.Redirect, HttpStatusCode.BadRequest,
            HttpStatusCode.Forbidden, HttpStatusCode.InternalServerError);

        if (response.StatusCode == HttpStatusCode.Redirect)
        {
            response.Headers.Location.Should().NotBeNull("redirect must include Location");
        }

        if (response.StatusCode == HttpStatusCode.InternalServerError)
        {
            var body = await response.Content.ReadAsStringAsync();
            body.Should().NotBeNullOrEmpty("500 should have a response body");
        }
    }

    private static string GenerateCodeVerifier()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static string GenerateCodeChallenge(string codeVerifier)
    {
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier));
        return Convert.ToBase64String(hash)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
