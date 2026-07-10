using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Http.E2E;

/// <summary>
/// Validates the URL-versioning contract documented in
/// <c>doc/API_VERSIONING.md</c>:
/// <list type="bullet">
///   <item>Custom management API lives under <c>/api/v1/identity/</c>.</item>
///   <item>The pre-E3 path <c>/api/identity/</c> is no longer routed (404).</item>
///   <item>OIDC discovery + RFC 8414 server metadata are both exposed,
///         unversioned, and return identical documents.</item>
///   <item>SCIM 2.0 stays at <c>/scim/v2/</c> (RFC 7644 §3.13) and is
///         not also exposed under <c>/api/v1/</c>.</item>
/// </list>
/// </summary>
[Collection("HttpIdentity")]
public class ApiVersioningTests
{
    private readonly HttpIdentityFixture _fixture;
    private readonly HttpClient _http;

    public ApiVersioningTests(HttpIdentityFixture fixture)
    {
        _fixture = fixture;
        _http = fixture.Http;
    }

    // ── Management API path ──

    [Fact]
    public async Task ManagementApi_Versioned_Path_Is_Routed()
    {
        var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/identity/applications");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fixture.ManagementToken);

        var resp = await _http.SendAsync(req);

        // The fixture provides a valid management token, so a properly routed +
        // authorized GET must succeed. Anything else (including 401) means the
        // route did not resolve as expected.
        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            "/api/v1/identity/* must be served by the management facade with a valid bearer");
    }

    [Fact]
    public async Task ManagementApi_Legacy_Unversioned_Path_Is_Not_Routed()
    {
        var req = new HttpRequestMessage(HttpMethod.Get, "/api/identity/applications");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fixture.ManagementToken);

        var resp = await _http.SendAsync(req);

        resp.StatusCode.Should().Be(HttpStatusCode.NotFound,
            "the pre-E3 /api/identity/* path is not retained — see doc/API_VERSIONING.md");
    }

    // ── OIDC + RFC 8414 discovery ──

    [Fact]
    public async Task Discovery_Oidc_Endpoint_Is_Reachable_Without_Version_Prefix()
    {
        var resp = await _http.GetAsync("/.well-known/openid-configuration");

        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            "OIDC Discovery 1.0 fixes this URL — never version it");
        resp.Content.Headers.ContentType!.MediaType.Should().Be("application/json");
    }

    [Fact]
    public async Task Discovery_Rfc8414_OAuthServer_Endpoint_Is_Reachable()
    {
        var resp = await _http.GetAsync("/.well-known/oauth-authorization-server");

        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            "RFC 8414 metadata must be served for non-OIDC OAuth 2.0 clients");
        resp.Content.Headers.ContentType!.MediaType.Should().Be("application/json");
    }

    [Fact]
    public async Task Discovery_Oidc_And_Rfc8414_Return_Equivalent_Issuer()
    {
        var oidc = await GetJson("/.well-known/openid-configuration");
        var oauth = await GetJson("/.well-known/oauth-authorization-server");

        oidc.TryGetProperty("issuer", out var oidcIssuer).Should().BeTrue();
        oauth.TryGetProperty("issuer", out var oauthIssuer).Should().BeTrue(
            "RFC 8414 §2: 'issuer' is REQUIRED");
        oauthIssuer.GetString().Should().Be(oidcIssuer.GetString(),
            "both metadata documents describe the same authorization server");
    }

    // ── SCIM stays SCIM ──
    //
    // The positive case ("/scim/v2/* is reachable") is exercised across many
    // tests in tests/Scim/, against ProductionHttpFixture which actually
    // enables the SCIM facade. Here we only assert the negative: SCIM must
    // NOT also be mounted under /api/v1/ — see doc/API_VERSIONING.md.

    [Fact]
    public async Task Scim_Endpoint_Is_Not_Also_Mounted_Under_V1_Prefix()
    {
        var resp = await _http.GetAsync("/api/v1/scim/v2/ServiceProviderConfig");

        resp.StatusCode.Should().Be(HttpStatusCode.NotFound,
            "the original E3 draft mentioned /api/v1/scim/* — we do not ship that, " +
            "SCIM lives only at the RFC-defined /scim/v2/* path");
    }

    // ── Helpers ──

    private async Task<JsonElement> GetJson(string url)
    {
        var resp = await _http.GetAsync(url);
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await resp.Content.ReadAsStringAsync();
        return JsonDocument.Parse(body).RootElement;
    }
}
