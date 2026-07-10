using System.Net;
using System.Net.Http.Headers;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Http.E2E;

/// <summary>
/// E2E tests verifying the per-route CORS policy applied by <c>HttpFacadeRouteBuilder</c>.
/// <para>
/// Three policy classes are exercised:
/// </para>
/// <list type="bullet">
///   <item><b>Public</b> (<c>/.well-known/*</c>): wildcard origin, no credentials.</item>
///   <item><b>Client</b> (<c>/connect/token</c>, <c>/connect/userinfo</c>,
///   <c>/connect/introspect</c>, ...): origin must match either a registered application's
///   redirect URI or <c>HttpTransportOptions.Http.AdditionalAllowedOrigins</c>.</item>
///   <item><b>None</b> (<c>/api/v1/identity/*</c>, <c>/connect/authorize</c>): no CORS headers
///   ever \u2014 these endpoints are not reachable from cross-origin browser fetch.</item>
/// </list>
/// The fixture configures <c>AdditionalAllowedOrigins = "http://localhost:3000, http://localhost:5173"</c>.
/// </summary>
[Collection("HttpIdentity")]
public class CorsE2ETests
{
    private const string AllowedOrigin1 = "http://localhost:3000";
    private const string AllowedOrigin2 = "http://localhost:5173";
    private const string DisallowedOrigin = "https://evil.example.com";

    private readonly HttpIdentityFixture _fixture;
    private readonly HttpClient _http;

    public CorsE2ETests(HttpIdentityFixture fixture)
    {
        _fixture = fixture;
        _http = fixture.Http;
    }

    // ── Public policy (/.well-known/*): wildcard, no Origin needed ──

    [Fact]
    public async Task Discovery_Get_ReturnsWildcardCorsHeader()
    {
        var response = await _http.GetAsync("/.well-known/openid-configuration");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Headers.GetValues("Access-Control-Allow-Origin").Single()
            .Should().Be("*", "well-known endpoints are public per RFC 8414");
        response.Headers.Should().Contain(h => h.Key == "Vary",
            "Vary: Origin must be emitted whenever CORS dispatch runs");
    }

    [Fact]
    public async Task Discovery_Preflight_AnyOrigin_Returns204WithWildcard()
    {
        var request = new HttpRequestMessage(HttpMethod.Options, "/.well-known/openid-configuration");
        request.Headers.Add("Origin", DisallowedOrigin);
        request.Headers.Add("Access-Control-Request-Method", "GET");

        var response = await _http.SendAsync(request);

        response.StatusCode.Should().Be(HttpStatusCode.NoContent);
        response.Headers.GetValues("Access-Control-Allow-Origin").Single().Should().Be("*");
    }

    [Fact]
    public async Task Jwks_Get_ReturnsWildcardCorsHeader()
    {
        var response = await _http.GetAsync("/.well-known/jwks");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Headers.GetValues("Access-Control-Allow-Origin").Single().Should().Be("*");
    }

    // ── Client policy (token / userinfo / introspect): per-request resolver ──

    [Fact]
    public async Task Token_Post_AllowedOrigin_EchoesSingleOrigin()
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = "test-client"
            })
        };
        request.Headers.Add("Origin", AllowedOrigin1);

        var response = await _http.SendAsync(request);

        response.Headers.GetValues("Access-Control-Allow-Origin").Single()
            .Should().Be(AllowedOrigin1, "the resolver must echo a single matching origin");
    }

    [Fact]
    public async Task Token_Post_DisallowedOrigin_OmitsCorsHeader()
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = "test-client"
            })
        };
        request.Headers.Add("Origin", DisallowedOrigin);

        var response = await _http.SendAsync(request);

        response.Headers.Contains("Access-Control-Allow-Origin").Should().BeFalse(
            "an unregistered/un-listed origin must NOT receive CORS headers");
    }

    [Fact]
    public async Task Token_Preflight_AllowedOrigin_Returns204WithEcho()
    {
        var request = new HttpRequestMessage(HttpMethod.Options, "/connect/token");
        request.Headers.Add("Origin", AllowedOrigin1);
        request.Headers.Add("Access-Control-Request-Method", "POST");
        request.Headers.Add("Access-Control-Request-Headers", "content-type");

        var response = await _http.SendAsync(request);

        response.StatusCode.Should().Be(HttpStatusCode.NoContent);
        response.Headers.GetValues("Access-Control-Allow-Origin").Single().Should().Be(AllowedOrigin1);
        response.Headers.GetValues("Access-Control-Allow-Methods").Single()
            .Should().Contain("POST");
        response.Headers.GetValues("Access-Control-Allow-Headers").Single()
            .Should().Contain("content-type");
    }

    [Fact]
    public async Task Userinfo_Preflight_AllowedOrigin_Returns204WithEcho()
    {
        var request = new HttpRequestMessage(HttpMethod.Options, "/connect/userinfo");
        request.Headers.Add("Origin", AllowedOrigin2);
        request.Headers.Add("Access-Control-Request-Method", "GET");

        var response = await _http.SendAsync(request);

        response.StatusCode.Should().Be(HttpStatusCode.NoContent);
        response.Headers.GetValues("Access-Control-Allow-Origin").Single().Should().Be(AllowedOrigin2);
    }

    [Fact]
    public async Task Introspect_Post_AllowedOrigin_EchoesOrigin()
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/connect/introspect")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["token"] = "some-token",
                ["client_id"] = "test-client",
                ["client_secret"] = "secret"
            })
        };
        request.Headers.Add("Origin", AllowedOrigin1);

        var response = await _http.SendAsync(request);

        response.Headers.GetValues("Access-Control-Allow-Origin").Single().Should().Be(AllowedOrigin1);
    }

    // ── No-CORS policy: management API and authorize endpoint ──

    [Fact]
    public async Task ManagementApi_NeverEmitsCorsHeaders()
    {
        // The management API and SCIM are admin-only: no browser-side access path exists,
        // so even when CORS is globally enabled they remain transparent.
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/identity/applications");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fixture.ManagementToken);
        request.Headers.Add("Origin", AllowedOrigin1);

        var response = await _http.SendAsync(request);

        response.Headers.Contains("Access-Control-Allow-Origin").Should().BeFalse(
            "management API must never expose CORS \u2014 it is not browser-callable");
    }

    [Fact]
    public async Task Authorize_NeverEmitsCorsHeaders()
    {
        // /connect/authorize is a redirect endpoint (full-page navigation) \u2014 browsers
        // never issue cross-origin fetch against it, so emitting CORS headers would be
        // misleading.
        var request = new HttpRequestMessage(
            HttpMethod.Get,
            "/connect/authorize?response_type=code&client_id=x&redirect_uri=http://localhost/cb");
        request.Headers.Add("Origin", AllowedOrigin1);

        var response = await _http.SendAsync(request);

        response.Headers.Contains("Access-Control-Allow-Origin").Should().BeFalse(
            "authorize endpoint is browser-redirect-only");
    }
}
