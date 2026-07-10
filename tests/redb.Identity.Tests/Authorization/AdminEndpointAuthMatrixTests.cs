using System.Net;
using System.Net.Http.Headers;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Authorization;

/// <summary>
/// G14 — endpoint-matrix smoke for management-API authorization.
/// <para>
/// The HTTP facade routes management endpoints through
/// <c>ManagementBearerAuthProcessor</c> which requires a bearer access token whose
/// scopes intersect <c>{ identity:manage, identity:account, scim }</c> (see
/// <c>ProductionHttpFixture.InitializeAsync</c> wiring). This test asserts the
/// invariant per endpoint:
/// <list type="number">
///   <item>no token → <c>401</c> (cannot enumerate without an access token);</item>
///   <item>token without the required scope → <c>403</c> (e.g. <c>scim</c> token on
///         management routes, or <c>identity:manage</c> token on SCIM routes);</item>
///   <item>token with the right scope → <c>2xx</c>.</item>
/// </list>
/// </para>
/// <para>
/// Without this matrix, a refactor that drops <c>ManagementBearerAuthProcessor</c>
/// from a single endpoint would silently expose admin operations to unauthenticated
/// callers — exactly the IDOR-shaped regression that G14 / B8 aims to lock down.
/// </para>
/// </summary>
[Collection("ProductionHttp")]
public sealed class AdminEndpointAuthMatrixTests
{
    private readonly ProductionHttpFixture _fx;

    public AdminEndpointAuthMatrixTests(ProductionHttpFixture fx) => _fx = fx;

    /// <summary>Endpoints requiring <c>identity:manage</c> (or <c>identity:account</c> when self-scoped).</summary>
    public static IEnumerable<object[]> ManagementEndpoints() => new[]
    {
        new object[] { "GET",  "/api/v1/identity/users" },
        new object[] { "GET",  "/api/v1/identity/scopes" },
        new object[] { "GET",  "/api/v1/identity/sessions?userId=1" },
    };

    /// <summary>SCIM endpoints requiring the <c>scim</c> scope.</summary>
    public static IEnumerable<object[]> ScimEndpoints() => new[]
    {
        new object[] { "GET", "/scim/v2/Users" },
        new object[] { "GET", "/scim/v2/Groups" },
    };

    [Theory]
    [MemberData(nameof(ManagementEndpoints))]
    public async Task ManagementEndpoint_WithoutBearerToken_Returns401(string method, string path)
    {
        using var req = new HttpRequestMessage(new HttpMethod(method), path);

        var resp = await _fx.Http.SendAsync(req);

        ((int)resp.StatusCode).Should().Be(401,
            "{0} {1}: management API must reject anonymous calls — without this guard " +
            "every Manage* route would be open to the internet (G14 / B8).",
            method, path);
    }

    [Theory]
    [MemberData(nameof(ManagementEndpoints))]
    public async Task ManagementEndpoint_WithScimOnlyToken_Returns403(string method, string path)
    {
        using var req = new HttpRequestMessage(new HttpMethod(method), path);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fx.ScimToken);

        var resp = await _fx.Http.SendAsync(req);

        // 403 (forbidden) is correct; 401 also acceptable if the validator strips
        // mismatched-scope tokens. The critical assertion is that the call is NOT
        // allowed (2xx) — that would be cross-scope privilege escalation.
        var code = (int)resp.StatusCode;
        (code == 401 || code == 403).Should().BeTrue(
            "{0} {1}: a SCIM-only token must NOT reach management endpoints (got {2}). " +
            "Allowing it would let a SCIM provisioner perform admin mutations.",
            method, path, code);
    }

    [Theory]
    [MemberData(nameof(ManagementEndpoints))]
    public async Task ManagementEndpoint_WithManagementToken_Returns2xx(string method, string path)
    {
        using var req = new HttpRequestMessage(new HttpMethod(method), path);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fx.ManagementToken);

        var resp = await _fx.Http.SendAsync(req);

        ((int)resp.StatusCode).Should().BeInRange(200, 299,
            "{0} {1}: a token bearing identity:manage must be admitted. " +
            "Status: {2}", method, path, resp.StatusCode);
    }

    [Theory]
    [MemberData(nameof(ScimEndpoints))]
    public async Task ScimEndpoint_WithoutBearerToken_Returns401(string method, string path)
    {
        using var req = new HttpRequestMessage(new HttpMethod(method), path);

        var resp = await _fx.Http.SendAsync(req);

        ((int)resp.StatusCode).Should().Be(401,
            "{0} {1}: SCIM API must reject anonymous calls (RFC 7644 §2).", method, path);
    }

    [Theory]
    [MemberData(nameof(ScimEndpoints))]
    public async Task ScimEndpoint_WithManagementToken_IsRejected(string method, string path)
    {
        // Symmetry: a non-SCIM token must NOT pass the SCIM authorization gate.
        // Otherwise an admin could side-step provisioning audit by crossing scopes.
        using var req = new HttpRequestMessage(new HttpMethod(method), path);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fx.ManagementToken);

        var resp = await _fx.Http.SendAsync(req);

        var code = (int)resp.StatusCode;
        (code == 401 || code == 403).Should().BeTrue(
            "{0} {1}: a management-only token must NOT pass the SCIM scope gate (got {2}). " +
            "Cross-scope acceptance is a privilege-boundary violation.",
            method, path, code);
    }

    [Theory]
    [MemberData(nameof(ScimEndpoints))]
    public async Task ScimEndpoint_WithScimToken_Returns2xx(string method, string path)
    {
        using var req = new HttpRequestMessage(new HttpMethod(method), path);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fx.ScimToken);

        var resp = await _fx.Http.SendAsync(req);

        ((int)resp.StatusCode).Should().BeInRange(200, 299,
            "{0} {1}: a token bearing 'scim' must be admitted. Status: {2}",
            method, path, resp.StatusCode);
    }
}
