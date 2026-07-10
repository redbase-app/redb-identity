using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// Full-cycle E2E test for Demonstrating Proof of Possession (RFC 9449 / Z4).
/// Scenarios:
/// 1. Discovery advertises <c>dpop_signing_alg_values_supported</c>.
/// 2. POST /connect/token with a valid DPoP proof yields <c>token_type=DPoP</c> and access token containing <c>cnf.jkt</c>.
/// 3. Replay of the same DPoP proof at /token is rejected with <c>invalid_dpop_proof</c>.
/// 4. Soft-mode default: requests without the DPoP header still succeed and return Bearer tokens.
/// </summary>
[Collection("ProductionHttp")]
public class DpopFullCycleTests
{
    private readonly ProductionHttpFixture _fx;

    public DpopFullCycleTests(ProductionHttpFixture fx) => _fx = fx;

    [Fact]
    public async Task Discovery_Advertises_Dpop_Signing_Algs_When_Enabled()
    {
        var resp = await _fx.Http.GetAsync("/.well-known/openid-configuration");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var json = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;

        json.TryGetProperty("dpop_signing_alg_values_supported", out var algs)
            .Should().BeTrue("RFC 9449 §5.1: when DPoP is enabled the discovery doc must advertise the supported algs");
        algs.ValueKind.Should().Be(JsonValueKind.Array);
        var values = algs.EnumerateArray().Select(e => e.GetString()).ToArray();
        values.Should().Contain("ES256");
    }

    [Fact]
    public async Task Token_With_Valid_DPoP_Proof_Returns_DPoP_TokenType_And_Cnf_Jkt_In_AccessToken()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var url = $"{_fx.BaseUrl.TrimEnd('/')}/connect/token";
        var proof = BuildDpopProof(ec, "POST", url);

        using var req = BuildPasswordTokenRequest();
        req.Headers.Add("DPoP", proof);

        var resp = await _fx.Http.SendAsync(req);
        var bodyStr = await resp.Content.ReadAsStringAsync();
        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            "token request with valid DPoP proof must succeed: {0}", bodyStr);

        var json = JsonDocument.Parse(bodyStr).RootElement;
        json.GetProperty("token_type").GetString().Should().Be("DPoP",
            "RFC 9449 §6: when proof is bound, token_type MUST be 'DPoP'");

        var accessToken = json.GetProperty("access_token").GetString()!;
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(accessToken);
        jwt.TryGetPayloadValue<JsonElement>("cnf", out var cnf).Should().BeTrue(
            "RFC 9449 §6.1: access tokens bound to a DPoP key MUST carry a 'cnf' claim");
        cnf.GetProperty("jkt").GetString().Should().Be(ComputeJkt(ec));
    }

    [Fact]
    public async Task Token_With_Replayed_DPoP_Proof_Is_Rejected()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var url = $"{_fx.BaseUrl.TrimEnd('/')}/connect/token";
        var proof = BuildDpopProof(ec, "POST", url);

        using var req1 = BuildPasswordTokenRequest();
        req1.Headers.Add("DPoP", proof);
        var first = await _fx.Http.SendAsync(req1);
        first.StatusCode.Should().Be(HttpStatusCode.OK);

        using var req2 = BuildPasswordTokenRequest();
        req2.Headers.Add("DPoP", proof);
        var second = await _fx.Http.SendAsync(req2);
        ((int)second.StatusCode).Should().BeGreaterOrEqualTo(400,
            "RFC 9449 §11.1: replayed DPoP proof must be rejected");
        var body = JsonDocument.Parse(await second.Content.ReadAsStringAsync()).RootElement;
        body.GetProperty("error").GetString().Should().Be("invalid_dpop_proof");
    }

    [Fact]
    public async Task Token_Without_DPoP_Header_Returns_Bearer_In_SoftMode()
    {
        using var req = BuildPasswordTokenRequest();
        var resp = await _fx.Http.SendAsync(req);

        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            "baseline token request without DPoP must succeed in soft-mode: {0}",
            await resp.Content.ReadAsStringAsync());
        var json = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        json.GetProperty("token_type").GetString().Should().Be("Bearer",
            "soft-mode default (RequireForAccessTokens=false): without DPoP header the server issues a plain Bearer token");
    }

    [Fact]
    public async Task Token_With_Wrong_HtmClaim_Is_Rejected()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var url = $"{_fx.BaseUrl.TrimEnd('/')}/connect/token";
        var proof = BuildDpopProof(ec, "GET", url); // wrong method

        using var req = BuildPasswordTokenRequest();
        req.Headers.Add("DPoP", proof);
        var resp = await _fx.Http.SendAsync(req);
        ((int)resp.StatusCode).Should().BeGreaterOrEqualTo(400);
        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        body.GetProperty("error").GetString().Should().Be("invalid_dpop_proof");
    }

    /// <summary>
    /// Builds a /token request authenticated with the confidential test client + ROPC.
    /// Adds Authorization: Basic with the client secret.
    /// </summary>
    private static HttpRequestMessage BuildPasswordTokenRequest()
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["username"] = ProductionHttpFixture.TestUsername,
                ["password"] = ProductionHttpFixture.TestPassword,
                ["scope"] = "openid"
            })
        };
        var basic = Convert.ToBase64String(Encoding.UTF8.GetBytes(
            $"{ProductionHttpFixture.TestClientId}:{ProductionHttpFixture.TestClientSecret}"));
        req.Headers.Authorization = new AuthenticationHeaderValue("Basic", basic);
        return req;
    }

    // ─── Helpers ───

    /// <summary>
    /// Builds an ES256 DPoP proof JWT carrying typ=dpop+jwt header, embedded jwk (public key only),
    /// and claims htm/htu/iat/jti per RFC 9449 §4.2.
    /// </summary>
    private static string BuildDpopProof(ECDsa ec, string method, string url)
    {
        var pubParams = ec.ExportParameters(includePrivateParameters: false);
        var jwk = new JsonWebKey
        {
            Kty = "EC",
            Crv = "P-256",
            X = Base64UrlEncoder.Encode(pubParams.Q.X!),
            Y = Base64UrlEncoder.Encode(pubParams.Q.Y!),
            Alg = "ES256",
        };

        var jwkJson = $"{{\"crv\":\"{jwk.Crv}\",\"kty\":\"{jwk.Kty}\",\"x\":\"{jwk.X}\",\"y\":\"{jwk.Y}\"}}";
        var headerJson = $"{{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":{jwkJson}}}";
        var iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var jti = Guid.NewGuid().ToString("N");
        var payloadJson = $"{{\"htm\":\"{method}\",\"htu\":\"{url}\",\"iat\":{iat},\"jti\":\"{jti}\"}}";

        var headerB64 = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(headerJson));
        var payloadB64 = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payloadJson));
        var signingInput = $"{headerB64}.{payloadB64}";
        var sig = ec.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256);
        var sigB64 = Base64UrlEncoder.Encode(sig);
        return $"{signingInput}.{sigB64}";
    }

    private static string ComputeJkt(ECDsa ec)
    {
        var pubParams = ec.ExportParameters(includePrivateParameters: false);
        // RFC 7638: SHA-256 of canonical JSON of the JWK with members in lex-order: crv,kty,x,y.
        var x = Base64UrlEncoder.Encode(pubParams.Q.X!);
        var y = Base64UrlEncoder.Encode(pubParams.Q.Y!);
        var canonical = $"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Base64UrlEncoder.Encode(hash);
    }
}
