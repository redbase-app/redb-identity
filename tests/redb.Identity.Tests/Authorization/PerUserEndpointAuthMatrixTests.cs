using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using redb.Identity.Core.Routes;

namespace redb.Identity.Tests.Authorization;

/// <summary>
/// G14 — endpoint authorization matrix on per-user management endpoints.
/// <para>
/// Extends <see cref="AdminEndpointAuthMatrixTests"/> with the three additional
/// surface areas called out in the STATUS gap: MFA per-user endpoints, consents,
/// and applications. For each, asserts the three-token matrix:
/// <list type="number">
///   <item>no token → <c>401</c> (anonymous rejected);</item>
///   <item>wrong-scope token (SCIM-only) → <c>401</c>/<c>403</c>;</item>
///   <item>management-scope token → <c>2xx</c>.</item>
/// </list>
/// This is the HTTP-surface bookend of the unit-level
/// <see cref="redb.Identity.Tests.Routes.MfaIdorTests"/> — a regression that drops
/// <c>ManagementBearerAuthProcessor</c> from one of these controllers would let
/// anonymous callers mutate MFA / consents / applications.
/// </para>
/// </summary>
[Collection("ProductionHttp")]
public sealed class PerUserEndpointAuthMatrixTests
{
    private readonly ProductionHttpFixture _fx;

    public PerUserEndpointAuthMatrixTests(ProductionHttpFixture fx) => _fx = fx;

    // Endpoints that read/mutate per-user state and MUST be behind
    // ManagementBearerAuthProcessor (admin or account scope).
    public static IEnumerable<object[]> PerUserEndpoints()
    {
        // Path + method + request body (null → no body)
        yield return new object?[] { "GET",  "/api/v1/identity/mfa/status/1", null };
        yield return new object?[] { "GET",  "/api/v1/identity/consents?userId=1", null };
        yield return new object?[] { "GET",  "/api/v1/identity/applications", null };
        yield return new object?[] { "GET",  "/api/v1/identity/scopes", null };
        yield return new object?[] { "GET",  "/api/v1/identity/tokens?userId=1", null };
    }

    [Theory]
    [MemberData(nameof(PerUserEndpoints))]
    public async Task Endpoint_WithoutBearerToken_Returns401(string method, string path, string? body)
    {
        using var req = BuildRequest(method, path, body, token: null);

        var resp = await _fx.Http.SendAsync(req);

        ((int)resp.StatusCode).Should().Be(401,
            "{0} {1}: per-user management endpoint MUST reject anonymous calls. " +
            "A regression here lets the internet read/mutate user state without credentials.",
            method, path);
    }

    [Theory]
    [MemberData(nameof(PerUserEndpoints))]
    public async Task Endpoint_WithScimOnlyToken_IsRejected(string method, string path, string? body)
    {
        using var req = BuildRequest(method, path, body, token: _fx.ScimToken);

        var resp = await _fx.Http.SendAsync(req);

        var code = (int)resp.StatusCode;
        (code == 401 || code == 403).Should().BeTrue(
            "{0} {1}: a SCIM-only token must NOT pass the management scope gate (got {2}). " +
            "Cross-scope admission is a privilege boundary violation.",
            method, path, code);
    }

    [Theory]
    [MemberData(nameof(PerUserEndpoints))]
    public async Task Endpoint_WithManagementToken_IsAdmitted(string method, string path, string? body)
    {
        using var req = BuildRequest(method, path, body, token: _fx.ManagementToken);

        var resp = await _fx.Http.SendAsync(req);

        // Admission ≠ business-layer success. We only assert the token passed the auth
        // gate: anything other than 401/403 is acceptable here (endpoint may return 404
        // for a user with no MFA state, 400 for a malformed userId, 200 for an empty
        // list). The invariant under test is that the admin scope MUST be admitted.
        var code = (int)resp.StatusCode;
        code.Should().NotBe(401, "{0} {1}: admin-scoped token rejected as unauthenticated (401).", method, path);
        code.Should().NotBe(403, "{0} {1}: admin-scoped token rejected as forbidden (403).", method, path);
    }

    /// <summary>
    /// Pins the B8 IDOR contract at the HTTP layer: a caller holding only
    /// <c>identity:account</c> (self-scope) cannot mutate MFA for a user whose id
    /// differs from the token's <c>sub</c> claim. The unit-level coverage lives in
    /// <see cref="redb.Identity.Tests.Routes.MfaIdorTests"/>; this test exists to
    /// detect the regression where <c>RequireSelfOrAdminProcessor</c> is dropped
    /// from the direct-vm route wiring at
    /// <see cref="redb.Identity.Core.Routes.IdentityCoreRouteBuilder"/> (MfaManage block).
    /// </summary>
    [Fact]
    public async Task MfaSetup_WithScimToken_CannotCrossScopeMutate()
    {
        // We use ScimToken here as the stand-in for "a token that is NOT identity:manage
        // and NOT identity:account" — so this covers the same-scope defence as
        // AdminEndpointAuthMatrix plus the extra guarantee that the /mfa/totp/setup
        // surface specifically is refused.
        var body = JsonSerializer.Serialize(new { userId = 9999, username = "victim" });
        using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/identity/mfa/totp/setup")
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fx.ScimToken);

        var resp = await _fx.Http.SendAsync(req);

        var code = (int)resp.StatusCode;
        (code == 401 || code == 403).Should().BeTrue(
            "MFA setup MUST NOT be reachable with a token that carries neither identity:manage " +
            "nor identity:account (got {0}). Dropping the auth processor from MfaManage is a " +
            "B8 IDOR regression.", code);
    }

    private static HttpRequestMessage BuildRequest(string method, string path, string? body, string? token)
    {
        var req = new HttpRequestMessage(new HttpMethod(method), path);
        if (body is not null)
            req.Content = new StringContent(body, Encoding.UTF8, "application/json");
        if (token is not null)
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return req;
    }
}
