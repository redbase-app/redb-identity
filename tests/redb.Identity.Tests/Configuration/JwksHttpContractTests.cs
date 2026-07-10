using System.Net;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Configuration;

/// <summary>
/// G12 — JWKS endpoint HTTP-surface guarantees.
/// <para>
/// <see cref="redb.Identity.Core.Routes.Processors.JwksEndpointProcessor"/> sets
/// <c>Cache-Control: public, max-age=3600</c> on every JWKS response. Relying parties
/// MUST cache JWKS (OIDC Core §10.1.1) but too-long a TTL delays detection of a
/// newly-rotated key. The 1-hour ceiling mirrors Microsoft / Google / Auth0 and sits
/// inside the typical 24–72h overlap window.
/// </para>
/// <para>
/// A regression that dropped the header would push RPs onto their own heuristics
/// (some cache forever, some never cache) and either (a) miss key rotations or
/// (b) hammer the JWKS endpoint on every token verify.
/// </para>
/// </summary>
[Collection("ProductionHttp")]
public sealed class JwksHttpContractTests
{
    private readonly ProductionHttpFixture _fx;

    public JwksHttpContractTests(ProductionHttpFixture fx) => _fx = fx;

    [Fact]
    public async Task Jwks_EmitsCacheControlHeader()
    {
        var resp = await _fx.Http.GetAsync("/.well-known/jwks");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);

        var cacheControl = resp.Headers.CacheControl?.ToString()
            ?? (resp.Content.Headers.TryGetValues("Cache-Control", out var v) ? string.Join(",", v) : null);

        cacheControl.Should().NotBeNullOrEmpty(
            "/.well-known/jwks MUST set Cache-Control. Without it RPs default to their own " +
            "heuristics — some cache forever (missing rotations), some never cache " +
            "(hammering the endpoint on every token verify).");

        cacheControl!.ToLowerInvariant().Should().Contain("public");
        cacheControl.ToLowerInvariant().Should().Contain("max-age=3600",
            "D2 pins JWKS max-age to 3600 — the RP-side refresh cadence. Tightening or " +
            "loosening without an RFC / spec reason is a silent protocol change.");
    }

    [Fact]
    public async Task Discovery_EmitsCacheControlHeader()
    {
        // Parallel guard for the discovery doc: D1/D2 sets max-age=300 (5 min) — small
        // enough to roll forward a config push, large enough to cut cold-start volume.
        var resp = await _fx.Http.GetAsync("/.well-known/openid-configuration");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);

        var cacheControl = resp.Headers.CacheControl?.ToString()
            ?? (resp.Content.Headers.TryGetValues("Cache-Control", out var v) ? string.Join(",", v) : null);

        cacheControl.Should().NotBeNullOrEmpty();
        cacheControl!.ToLowerInvariant().Should().Contain("max-age=300",
            "discovery doc is pinned at max-age=300 (D1/D2). Any deviation silently " +
            "changes RP cache behaviour.");
    }

    [Fact]
    public async Task Jwks_ResponseContainsKeysArray()
    {
        // Smoke: the endpoint returns a valid JWKS document (RFC 7517 §5: JSON object
        // with a "keys" array). Without this the Cache-Control is noise.
        var resp = await _fx.Http.GetAsync("/.well-known/jwks");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await resp.Content.ReadAsStringAsync();
        body.Should().Contain("\"keys\"",
            "RFC 7517 §5: JWKS document MUST have a top-level 'keys' array. A regression " +
            "that returned an empty object / error envelope here would silently break " +
            "every RP's token-verify path.");
    }
}
