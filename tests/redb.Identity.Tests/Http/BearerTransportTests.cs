using System.Net;
using System.Net.Http.Headers;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Http;

/// <summary>
/// G9 / D6 — bearer-token transport rules.
/// <para>
/// Protected endpoints (userinfo, management API, SCIM) accept the access token
/// ONLY in the <c>Authorization: Bearer</c> header per RFC 6750 §2. Identity
/// deliberately does NOT honour RFC 6750 §2.3 (URI query parameter) because:
/// <list type="bullet">
///   <item>Query-string tokens leak into access logs, proxy logs, <c>Referer</c>
///   headers, and browser history;</item>
///   <item>The RFC's own §2.3 is advisory and marked "SHOULD NOT use";</item>
///   <item>Major IdPs (Auth0, Okta, Google) disabled query-param bearer years ago.</item>
/// </list>
/// These tests pin the contract so a future "helpful" refactor that enables query
/// bearer cannot ship without noise.
/// </para>
/// </summary>
[Collection("ProductionHttp")]
public sealed class BearerTransportTests
{
    private readonly ProductionHttpFixture _fx;

    public BearerTransportTests(ProductionHttpFixture fx) => _fx = fx;

    [Fact]
    public async Task ManagementApi_WithBearerInQueryString_IsRejected()
    {
        // Use a valid management token but present it in the query string rather than
        // the Authorization header. The server must ignore the query param entirely
        // and reject the call as anonymous.
        var path = $"/api/v1/identity/users?access_token={Uri.EscapeDataString(_fx.ManagementToken)}";
        using var req = new HttpRequestMessage(HttpMethod.Get, path);

        var resp = await _fx.Http.SendAsync(req);

        ((int)resp.StatusCode).Should().Be(401,
            "access_token in the query string MUST NOT authenticate the caller (D6). " +
            "Otherwise a bearer token accidentally logged by an upstream proxy / " +
            "browser history / server access log would remain a usable credential " +
            "until expiry. Response: {0}", resp.StatusCode);
    }

    [Fact]
    public async Task Userinfo_WithBearerInQueryString_IsRejected()
    {
        // Userinfo is the canonical browser-facing protected endpoint — extra
        // important that it never honours query-string bearer (it WOULD end up
        // in Referer headers to third-party analytics scripts).
        var path = $"/connect/userinfo?access_token={Uri.EscapeDataString(_fx.ManagementToken)}";
        using var req = new HttpRequestMessage(HttpMethod.Get, path);

        var resp = await _fx.Http.SendAsync(req);

        ((int)resp.StatusCode).Should().BeOneOf(new[] { 400, 401 },
            "/connect/userinfo with access_token in the URL must reject — Referer leakage " +
            "to third-party scripts loaded by the redirecting client would otherwise " +
            "export the token to the entire ad/analytics graph. OpenIddict may answer " +
            "401 (missing bearer) or 400 (invalid_request) depending on pipeline order; " +
            "either is an acceptable rejection, but 2xx is a privacy regression.");
    }

    [Theory]
    [InlineData("bearer")]      // RFC 6750 §2.1: case-insensitive scheme
    [InlineData("BEARER")]
    [InlineData("BeArEr")]
    public async Task ManagementApi_AcceptsBearerSchemeCaseInsensitively(string schemeCasing)
    {
        // RFC 6750 §2.1 / D6: the scheme token is case-insensitive. Clients in the wild
        // (including some enterprise proxies) uppercase it; rejecting them would be
        // non-interop. The parser under test is the one in HttpIdentityProcessors.
        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/identity/users");
        req.Headers.TryAddWithoutValidation("Authorization", $"{schemeCasing} {_fx.ManagementToken}");

        var resp = await _fx.Http.SendAsync(req);

        ((int)resp.StatusCode).Should().BeInRange(200, 299,
            "bearer scheme is case-insensitive per RFC 6750 §2.1 — '{0}' must be " +
            "accepted. A regression that exact-matched 'Bearer' would break " +
            "interop with legitimate clients. Status: {1}", schemeCasing, resp.StatusCode);
    }

    [Fact]
    public async Task ManagementApi_WithoutAuthorizationHeader_Returns401()
    {
        // Pure negative: no Authorization header at all → 401. The Retry-After-ish
        // sibling is already in AdminEndpointAuthMatrixTests; this is the D6 shape.
        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/identity/users");
        var resp = await _fx.Http.SendAsync(req);
        ((int)resp.StatusCode).Should().Be(401);
    }

    [Fact]
    public async Task ManagementApi_WithMalformedBearerHeader_Returns401()
    {
        // Authorization header without a token value, or with Basic scheme, or just
        // "Bearer" → 401 (parser rejects rather than silently accepting).
        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/identity/users");
        req.Headers.TryAddWithoutValidation("Authorization", "Bearer");

        var resp = await _fx.Http.SendAsync(req);
        ((int)resp.StatusCode).Should().Be(401,
            "an Authorization header with scheme 'Bearer' but no token MUST 401 — " +
            "silently treating it as 'no token' is fine, but it must never be " +
            "interpreted as a blank token that passes validation.");
    }
}
