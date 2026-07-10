using System.Net;
using System.Net.Http.Headers;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Http;

/// <summary>
/// G9 — CORS preflight behaviour of the discovery / JWKS endpoints.
/// <para>
/// <see cref="redb.Identity.Http.HttpFacadeRouteBuilder.PublicCorsParams"/> emits
/// <c>corsOrigins=*</c> for <c>/.well-known/*</c> so every relying party (any SPA,
/// any CLI) can fetch discovery and JWKS without being registered in advance. This
/// matches RFC 8414 §3 and OIDC Core §10.1.1 (JWKS is public by design).
/// </para>
/// <para>
/// The test asserts two things:
/// <list type="number">
///   <item>An <c>OPTIONS</c> preflight with an arbitrary <c>Origin</c> succeeds and
///   returns <c>Access-Control-Allow-Origin: *</c>;</item>
///   <item>Token/userinfo endpoints (protected-ish) do NOT echo an arbitrary
///   unregistered origin — the resolver composes the registered-client whitelist
///   and <c>AdditionalAllowedOrigins</c>, and a stranger origin gets no ACAO header.</item>
/// </list>
/// Without these invariants an attacker could (a) tamper with discovery via a CORS
/// reflection attack on a misconfigured browser, or (b) exfiltrate tokens from any
/// origin via <c>/connect/token</c> XHR.
/// </para>
/// </summary>
[Collection("HttpIdentity")]
public sealed class CorsTests
{
    private readonly HttpIdentityFixture _fx;

    public CorsTests(HttpIdentityFixture fx) => _fx = fx;

    [Theory]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/oauth-authorization-server")]
    [InlineData("/.well-known/jwks")]
    public async Task Discovery_OptionsPreflight_AllowsAnyOrigin(string path)
    {
        using var req = new HttpRequestMessage(HttpMethod.Options, path);
        req.Headers.Add("Origin", "https://evil.example.com");
        req.Headers.Add("Access-Control-Request-Method", "GET");

        var resp = await _fx.Http.SendAsync(req);

        ((int)resp.StatusCode).Should().BeInRange(200, 299,
            "OPTIONS preflight on public discovery MUST succeed regardless of origin — " +
            "RFC 8414 §3 requires the metadata document be world-readable. Got {0} for {1}.",
            resp.StatusCode, path);

        var allow = resp.Headers.TryGetValues("Access-Control-Allow-Origin", out var v)
            ? string.Join(",", v) : null;
        allow.Should().Be("*",
            "public discovery endpoints emit corsOrigins=* (HttpFacadeRouteBuilder.PublicCorsParams). " +
            "Any relying party — SPAs, CLIs, new clients not yet registered — must be able to " +
            "read discovery and JWKS. Anything narrower breaks zero-config OIDC consumers.");
    }

    [Fact]
    public async Task TokenEndpoint_OptionsPreflightFromUnregisteredOrigin_DoesNotEchoOrigin()
    {
        // /connect/token uses ClientCorsParams which runs through the registered-client
        // resolver. A stranger origin that is NOT registered and NOT in
        // AdditionalAllowedOrigins must receive NO Access-Control-Allow-Origin header.
        // The preflight itself may return 200 / 204 (the middleware replies method-agnostic),
        // but the absence of ACAO means the browser blocks the actual CORS request.
        using var req = new HttpRequestMessage(HttpMethod.Options, "/connect/token");
        req.Headers.Add("Origin", "https://evil.example.com");
        req.Headers.Add("Access-Control-Request-Method", "POST");

        var resp = await _fx.Http.SendAsync(req);

        var allow = resp.Headers.TryGetValues("Access-Control-Allow-Origin", out var v)
            ? string.Join(",", v) : null;

        allow.Should().NotBe("*",
            "/connect/token must NEVER echo '*' — it carries refresh-token credentials " +
            "and wildcards+credentials would allow cross-origin token theft.");

        if (!string.IsNullOrEmpty(allow))
        {
            allow.Should().NotBe("https://evil.example.com",
                "an unregistered origin must not be echoed — otherwise any random site " +
                "could mount XHR token-endpoint attacks against authenticated browsers.");
        }
    }
}
