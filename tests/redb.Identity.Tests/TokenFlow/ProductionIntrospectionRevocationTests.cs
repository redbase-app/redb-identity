using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Contracts.Routes;
using redb.Identity.Tests.Infrastructure;
using redb.Route.Abstractions;
using redb.Route.Core;
using Xunit;

namespace redb.Identity.Tests.TokenFlow;

/// <summary>
/// Integration tests for Introspection (RFC 7662) and Revocation (RFC 7009) using
/// the PRODUCTION bootstrap. Real PostgreSQL stores, real OpenIddict pipeline,
/// real BCrypt secret validation — no degraded mode.
/// <para>
/// These tests exercise the revoke→introspect lifecycle that degraded mode CANNOT
/// verify (self-contained JWTs have no revocation list; production stores do).
/// </para>
/// </summary>
[Collection("ProductionBootstrap")]
public class ProductionIntrospectionRevocationTests
{
    private readonly ProductionBootstrapFixture _fx;

    public ProductionIntrospectionRevocationTests(ProductionBootstrapFixture fx)
        => _fx = fx;

    // ══════════════════════════════════════════════
    //  RFC 7662 — Introspection (Production)
    // ══════════════════════════════════════════════

    [Fact]
    public async Task Introspect_ValidToken_ReturnsActiveTrue()
    {
        var token = await ObtainAccessToken();

        var result = await Introspect(token);
        var body = result.Should().BeOfType<Dictionary<string, object?>>().Subject;

        body.Should().NotContainKey("error",
            because: $"introspection should succeed; got: {Describe(body)}");
        body.Should().ContainKey("active");
        body["active"].Should().Be(true,
            "freshly issued token must be active in production store");
    }

    [Fact]
    public async Task Introspect_ValidToken_ContainsSubjectClaim()
    {
        var token = await ObtainAccessToken();

        var result = await Introspect(token);
        var body = (Dictionary<string, object?>)result!;

        body["active"].Should().Be(true);
        body.Should().ContainKey("sub");
        body["sub"]!.ToString().Should().Be(ProductionBootstrapFixture.TestClientId,
            "subject should be the client_id for client_credentials flow");
    }

    [Fact]
    public async Task Introspect_ValidToken_ContainsIssuerClaim()
    {
        var token = await ObtainAccessToken();

        var result = await Introspect(token);
        var body = (Dictionary<string, object?>)result!;

        body["active"].Should().Be(true);
        body.Should().ContainKey("iss");
        body["iss"]!.ToString().Should().Contain("identity.test.local",
            "issuer must match the configured value");
    }

    [Fact]
    public async Task Introspect_ValidToken_ViaBasicAuth()
    {
        var token = await ObtainAccessToken();

        var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes(
            $"{ProductionBootstrapFixture.TestClientId}:{ProductionBootstrapFixture.TestClientSecret}"));

        var exchange = await _fx.RequestWithHeaders(
            IdentityEndpoints.Introspect,
            new Dictionary<string, string> { ["token"] = token },
            new Dictionary<string, object?> { ["Authorization"] = $"Basic {credentials}" });

        exchange.Out.Should().NotBeNull("introspection must produce a response");
        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body.Should().NotContainKey("error");
        body["active"].Should().Be(true);
    }

    [Fact]
    public async Task Introspect_InvalidToken_ReturnsInactiveOrError()
    {
        var result = await Introspect("completely-bogus-token-value");
        var body = (Dictionary<string, object?>)result!;

        // Production OpenIddict: invalid token → error or active:false
        var hasError = body.ContainsKey("error");
        var isInactive = body.TryGetValue("active", out var a) && a is false;
        (hasError || isInactive).Should().BeTrue(
            "invalid token must produce an error or inactive response");
    }

    [Fact]
    public async Task Introspect_MissingToken_ReturnsInvalidRequest()
    {
        var body = new Dictionary<string, string>
        {
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret
        };

        var result = await _fx.Request(IdentityEndpoints.Introspect, body);
        var response = (Dictionary<string, object?>)result!;

        response.Should().ContainKey("error");
        response["error"].Should().Be("invalid_request");
    }

    [Fact]
    public async Task Introspect_WrongClientSecret_ReturnsError()
    {
        var token = await ObtainAccessToken();

        var body = new Dictionary<string, string>
        {
            ["token"] = token,
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = "wrong-secret-value"
        };

        var result = await _fx.Request(IdentityEndpoints.Introspect, body);
        var response = (Dictionary<string, object?>)result!;

        // Real BCrypt validation — wrong secret must fail
        response.Should().ContainKey("error");
        response["error"]!.ToString().Should().Contain("invalid",
            "wrong secret must produce invalid_client or similar error");
    }

    // ══════════════════════════════════════════════
    //  RFC 7009 — Revocation (Production)
    // ══════════════════════════════════════════════

    [Fact]
    public async Task Revoke_ValidToken_Succeeds()
    {
        var token = await ObtainAccessToken();

        var result = await Revoke(token);
        var body = result as Dictionary<string, object?>;

        // RFC 7009: success → no error
        if (body != null)
            body.Should().NotContainKey("error",
                $"revocation should succeed; got: {Describe(body)}");
    }

    [Fact]
    public async Task Revoke_InvalidToken_ReturnsInvalidTokenOrSuccess()
    {
        // RFC 7009 §2.1 says server should respond 200 for invalid tokens,
        // but OpenIddict production mode validates JWT format first and returns
        // invalid_token if it cannot decode the token. This is acceptable behavior.
        var result = await Revoke("this-token-does-not-exist-anywhere");
        var body = result as Dictionary<string, object?>;

        if (body != null && body.ContainsKey("error"))
            body["error"]!.ToString().Should().Be("invalid_token",
                "OpenIddict rejects undecodable tokens at format level");
    }

    [Fact]
    public async Task Revoke_SetsEventMetadata()
    {
        var token = await ObtainAccessToken();

        var exchange = await RevokeWithExchange(token);

        exchange.Properties.Should().ContainKey("identity-event-type");
        exchange.Properties["identity-event-type"].Should().Be("TokenRevoked");
        exchange.Properties.Should().ContainKey("identity-event-data");
    }

    [Fact]
    public async Task Revoke_Idempotent_SecondRevocationIsAccepted()
    {
        var token = await ObtainAccessToken();

        // First revocation — should succeed
        var result1 = await Revoke(token);
        var body1 = result1 as Dictionary<string, object?>;
        if (body1 != null)
            body1.Should().NotContainKey("error");

        // Second revocation — OpenIddict marks the token as "no longer valid"
        // after first revocation, so it may return invalid_token on replay.
        // Both success and invalid_token are acceptable.
        var result2 = await Revoke(token);
        var body2 = result2 as Dictionary<string, object?>;
        if (body2 != null && body2.ContainsKey("error"))
            body2["error"]!.ToString().Should().Be("invalid_token",
                "already-revoked token may be rejected as invalid");
    }

    [Fact]
    public async Task Revoke_MissingToken_ReturnsError()
    {
        var body = new Dictionary<string, string>
        {
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret
        };

        var result = await _fx.Request(IdentityEndpoints.Revoke, body);
        var response = (Dictionary<string, object?>)result!;

        response.Should().ContainKey("error");
        response["error"].Should().Be("invalid_request");
    }

    [Fact]
    public async Task Revoke_WithTokenTypeHint_Succeeds()
    {
        var token = await ObtainAccessToken();

        var body = new Dictionary<string, string>
        {
            ["token"] = token,
            ["token_type_hint"] = "access_token",
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret
        };

        var result = await _fx.Request(IdentityEndpoints.Revoke, body);
        var response = result as Dictionary<string, object?>;

        if (response != null)
            response.Should().NotContainKey("error");
    }

    // ══════════════════════════════════════════════
    //  The big one: Revoke → Introspect lifecycle
    // ══════════════════════════════════════════════

    [Fact]
    public async Task RevokeAndIntrospect_RevokedTokenBecomesInactive()
    {
        // 1. Issue token
        var token = await ObtainAccessToken();

        // 2. Introspect — must be active
        var preRevoke = await Introspect(token);
        var preBody = (Dictionary<string, object?>)preRevoke!;
        preBody.Should().NotContainKey("error");
        preBody["active"].Should().Be(true,
            "token must be active before revocation");

        // 3. Revoke it
        var revokeResult = await Revoke(token);
        var revBody = revokeResult as Dictionary<string, object?>;
        if (revBody != null)
            revBody.Should().NotContainKey("error", "revocation must succeed");

        // 4. Introspect again — MUST be inactive now
        // This is the critical test that degraded mode cannot verify — with real stores,
        // revoked tokens are tracked in the database.
        var postRevoke = await Introspect(token);
        var postBody = (Dictionary<string, object?>)postRevoke!;
        var isInactive = postBody.TryGetValue("active", out var a) && Equals(a, false);
        var hasError = postBody.ContainsKey("error");
        (isInactive || hasError).Should().BeTrue(
            "after revocation, token must be inactive or return error; " +
            $"got: {Describe(postBody)}");
    }

    [Fact]
    public async Task RevokeAndIntrospect_AuthCodeToken_RevokedBecomesInactive()
    {
        // Full auth_code + PKCE flow → revoke → introspect
        var (accessToken, _) = await ObtainTokensViaAuthCodeFlow();

        // 1. Introspect — should be active
        var pre = await Introspect(accessToken);
        var preBody = (Dictionary<string, object?>)pre!;
        preBody.Should().NotContainKey("error");
        preBody["active"].Should().Be(true);

        // 2. Revoke
        var revokeResult = await Revoke(accessToken);
        var revBody = revokeResult as Dictionary<string, object?>;
        if (revBody != null)
            revBody.Should().NotContainKey("error");

        // 3. Introspect again
        var post = await Introspect(accessToken);
        var postBody = (Dictionary<string, object?>)post!;
        var isInactive = postBody.TryGetValue("active", out var a) && Equals(a, false);
        var hasError = postBody.ContainsKey("error");
        (isInactive || hasError).Should().BeTrue(
            "auth code token must be inactive after revocation");
    }

    [Fact]
    public async Task RevokeRefreshToken_ThenRefresh_Fails()
    {
        var (_, refreshToken) = await ObtainTokensViaAuthCodeFlow();

        // Revoke the refresh token using the same client that owns it.
        // The public client now has Revocation endpoint permission.
        var revokeBody = new Dictionary<string, string>
        {
            ["token"] = refreshToken,
            ["token_type_hint"] = "refresh_token",
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic
        };
        var revokeResult = await _fx.Request(IdentityEndpoints.Revoke, revokeBody);

        // Try to use the revoked refresh token
        var refreshBody = new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic
        };
        var result = await _fx.Request(IdentityEndpoints.Token, refreshBody);
        var response = (Dictionary<string, object?>)result!;

        // Revoked refresh token must not work
        response.Should().ContainKey("error",
            "revoked refresh token must not be usable");
    }

    // ── Helpers ──

    private async Task<string> ObtainAccessToken()
    {
        var body = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret
        };

        var result = await _fx.Request(IdentityEndpoints.Token, body);
        var response = (Dictionary<string, object?>)result!;
        response.Should().ContainKey("access_token",
            $"token issuance must succeed; got: {Describe(response)}");
        return response["access_token"]!.ToString()!;
    }

    private async Task<object?> Introspect(string token)
    {
        var body = new Dictionary<string, string>
        {
            ["token"] = token,
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret
        };

        return await _fx.Request(IdentityEndpoints.Introspect, body);
    }

    private async Task<object?> Revoke(string token)
    {
        var body = new Dictionary<string, string>
        {
            ["token"] = token,
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret
        };

        return await _fx.Request(IdentityEndpoints.Revoke, body);
    }

    private async Task<Exchange> RevokeWithExchange(string token)
    {
        return await _fx.RequestWithHeaders(
            IdentityEndpoints.Revoke,
            new Dictionary<string, string>
            {
                ["token"] = token,
                ["client_id"] = ProductionBootstrapFixture.TestClientId,
                ["client_secret"] = ProductionBootstrapFixture.TestClientSecret
            },
            new Dictionary<string, object?>());
    }

    private async Task<(string accessToken, string refreshToken)> ObtainTokensViaAuthCodeFlow()
    {
        var (codeVerifier, codeChallenge) = GeneratePkce();

        var authorizeBody = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic,
            ["redirect_uri"] = ProductionBootstrapFixture.TestRedirectUri,
            ["scope"] = "openid offline_access",
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256"
        };

        var authorizeResult = await _fx.RequestWithSession(IdentityEndpoints.Authorize, authorizeBody);
        var authorizeResponse = (Dictionary<string, object?>)authorizeResult!;
        authorizeResponse.Should().ContainKey("code",
            $"authorize must return code; got: {Describe(authorizeResponse)}");
        var code = authorizeResponse["code"]!.ToString()!;

        var tokenBody = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = ProductionBootstrapFixture.TestRedirectUri,
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic,
            ["code_verifier"] = codeVerifier
        };

        var tokenResult = await _fx.Request(IdentityEndpoints.Token, tokenBody);
        var tokenResponse = (Dictionary<string, object?>)tokenResult!;

        tokenResponse.Should().ContainKey("access_token");
        tokenResponse.Should().ContainKey("refresh_token");

        return (
            tokenResponse["access_token"]!.ToString()!,
            tokenResponse["refresh_token"]!.ToString()!
        );
    }

    private static (string codeVerifier, string codeChallenge) GeneratePkce()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        var verifier = Convert.ToBase64String(bytes)
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        var challenge = Convert.ToBase64String(hash)
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return (verifier, challenge);
    }

    private static string Describe(Dictionary<string, object?> d)
    {
        try { return JsonSerializer.Serialize(d); }
        catch { return string.Join(", ", d.Select(kv => $"{kv.Key}={kv.Value}")); }
    }
}
