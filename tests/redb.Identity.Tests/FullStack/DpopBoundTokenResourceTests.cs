using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AwesomeAssertions;
using Microsoft.IdentityModel.Tokens;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// RFC 9449 §7: a DPoP-bound access token (cnf.jkt) is usable at the server's own protected endpoints,
/// /connect/userinfo and the management API, only under the <c>DPoP</c> scheme with a fresh proof signed by
/// the bound key and carrying the token hash (<c>ath</c>). Without the proof it must not work as a bearer token.
/// </summary>
[Collection("ProductionHttp")]
public class DpopBoundTokenResourceTests
{
    private const string UserinfoPath = "/connect/userinfo";
    private const string ManagementPath = "/api/v1/identity/applications";

    private readonly ProductionHttpFixture _fx;

    public DpopBoundTokenResourceTests(ProductionHttpFixture fx) => _fx = fx;

    // ─── /connect/userinfo ───

    [Fact]
    public async Task Userinfo_BoundToken_AsBearerWithoutProof_IsRejected()
    {
        using var ec = NewKey();
        var token = await PasswordTokenAsync(ec);

        using var req = new HttpRequestMessage(HttpMethod.Get, UserinfoPath);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var resp = await _fx.Http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized, await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Userinfo_BoundToken_AsBearerWithValidProof_IsRejected()
    {
        using var ec = NewKey();
        var token = await PasswordTokenAsync(ec);

        using var req = new HttpRequestMessage(HttpMethod.Get, UserinfoPath);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        req.Headers.Add("DPoP", BuildProof(ec, "GET", Url(UserinfoPath), token));

        var resp = await _fx.Http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized, await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Userinfo_BoundToken_WithDpopSchemeAndValidProof_IsAccepted()
    {
        using var ec = NewKey();
        var token = await PasswordTokenAsync(ec);

        using var req = DpopRequest(HttpMethod.Get, UserinfoPath, token, BuildProof(ec, "GET", Url(UserinfoPath), token));

        var resp = await _fx.Http.SendAsync(req);
        var body = await resp.Content.ReadAsStringAsync();
        resp.StatusCode.Should().Be(HttpStatusCode.OK, body);
        JsonDocument.Parse(body).RootElement.TryGetProperty("sub", out _).Should().BeTrue();
    }

    [Fact]
    public async Task Userinfo_BoundToken_WithDpopSchemeAndProofWithoutAth_IsRejected()
    {
        using var ec = NewKey();
        var token = await PasswordTokenAsync(ec);

        using var req = DpopRequest(HttpMethod.Get, UserinfoPath, token, BuildProof(ec, "GET", Url(UserinfoPath), accessToken: null));

        var resp = await _fx.Http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized, await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Userinfo_BoundToken_WithProofFromAnotherKey_IsRejected()
    {
        using var ec = NewKey();
        using var other = NewKey();
        var token = await PasswordTokenAsync(ec);

        using var req = DpopRequest(HttpMethod.Get, UserinfoPath, token, BuildProof(other, "GET", Url(UserinfoPath), token));

        var resp = await _fx.Http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized, await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Userinfo_BoundToken_WithReplayedProof_IsRejected()
    {
        using var ec = NewKey();
        var token = await PasswordTokenAsync(ec);
        var proof = BuildProof(ec, "GET", Url(UserinfoPath), token);

        using var first = DpopRequest(HttpMethod.Get, UserinfoPath, token, proof);
        var firstResp = await _fx.Http.SendAsync(first);
        firstResp.StatusCode.Should().Be(HttpStatusCode.OK, await firstResp.Content.ReadAsStringAsync());

        using var second = DpopRequest(HttpMethod.Get, UserinfoPath, token, proof);
        var secondResp = await _fx.Http.SendAsync(second);
        secondResp.StatusCode.Should().Be(HttpStatusCode.Unauthorized, await secondResp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Userinfo_BoundToken_WithProofForAnotherUrl_IsRejected()
    {
        using var ec = NewKey();
        var token = await PasswordTokenAsync(ec);

        using var req = DpopRequest(HttpMethod.Get, UserinfoPath, token, BuildProof(ec, "GET", Url(ManagementPath), token));

        var resp = await _fx.Http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized, await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Userinfo_BoundToken_WithStaleProof_IsRejected()
    {
        using var ec = NewKey();
        var token = await PasswordTokenAsync(ec);
        var stale = DateTimeOffset.UtcNow.AddMinutes(-10);

        using var req = DpopRequest(HttpMethod.Get, UserinfoPath, token, BuildProof(ec, "GET", Url(UserinfoPath), token, stale));

        var resp = await _fx.Http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized, await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Userinfo_BoundToken_AsBearer_AnswersWithDpopChallenge()
    {
        using var ec = NewKey();
        var token = await PasswordTokenAsync(ec);

        using var req = new HttpRequestMessage(HttpMethod.Get, UserinfoPath);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var resp = await _fx.Http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        AssertDpopChallenge(resp);
    }

    [Fact]
    public async Task Userinfo_UnboundToken_WithDpopScheme_IsRejected()
    {
        var token = await PasswordTokenAsync(dpopKey: null);
        using var ec = NewKey();

        using var req = DpopRequest(HttpMethod.Get, UserinfoPath, token, BuildProof(ec, "GET", Url(UserinfoPath), token));

        var resp = await _fx.Http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized, await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Userinfo_UnboundToken_AsBearer_IsStillAccepted()
    {
        var token = await PasswordTokenAsync(dpopKey: null);

        using var req = new HttpRequestMessage(HttpMethod.Get, UserinfoPath);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var resp = await _fx.Http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.OK, await resp.Content.ReadAsStringAsync());
    }

    // ─── management API ───

    [Fact]
    public async Task Management_BoundToken_AsBearerWithoutProof_IsRejected()
    {
        using var ec = NewKey();
        var token = await ManagementTokenAsync(ec);

        using var req = new HttpRequestMessage(HttpMethod.Get, ManagementPath);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var resp = await _fx.Http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized, await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Management_BoundToken_WithDpopSchemeAndValidProof_IsAccepted()
    {
        using var ec = NewKey();
        var token = await ManagementTokenAsync(ec);

        using var req = DpopRequest(HttpMethod.Get, ManagementPath, token, BuildProof(ec, "GET", Url(ManagementPath), token));

        var resp = await _fx.Http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.OK, await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Management_BoundToken_WithReplayedProof_IsRejected()
    {
        using var ec = NewKey();
        var token = await ManagementTokenAsync(ec);
        var proof = BuildProof(ec, "GET", Url(ManagementPath), token);

        using var first = DpopRequest(HttpMethod.Get, ManagementPath, token, proof);
        var firstResp = await _fx.Http.SendAsync(first);
        firstResp.StatusCode.Should().Be(HttpStatusCode.OK, await firstResp.Content.ReadAsStringAsync());

        using var second = DpopRequest(HttpMethod.Get, ManagementPath, token, proof);
        var secondResp = await _fx.Http.SendAsync(second);
        secondResp.StatusCode.Should().Be(HttpStatusCode.Unauthorized, await secondResp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Management_BoundToken_WithProofForAnotherMethod_IsRejected()
    {
        using var ec = NewKey();
        var token = await ManagementTokenAsync(ec);

        using var req = DpopRequest(HttpMethod.Get, ManagementPath, token, BuildProof(ec, "POST", Url(ManagementPath), token));

        var resp = await _fx.Http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized, await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Management_BoundToken_WithStaleProof_IsRejected()
    {
        using var ec = NewKey();
        var token = await ManagementTokenAsync(ec);
        var stale = DateTimeOffset.UtcNow.AddMinutes(-10);

        using var req = DpopRequest(HttpMethod.Get, ManagementPath, token, BuildProof(ec, "GET", Url(ManagementPath), token, stale));

        var resp = await _fx.Http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized, await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Management_BoundToken_AsBearer_AnswersWithDpopChallenge()
    {
        using var ec = NewKey();
        var token = await ManagementTokenAsync(ec);

        using var req = new HttpRequestMessage(HttpMethod.Get, ManagementPath);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var resp = await _fx.Http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        AssertDpopChallenge(resp);
    }

    [Fact]
    public async Task Management_UnboundToken_WithDpopScheme_IsRejected()
    {
        using var ec = NewKey();

        using var req = DpopRequest(HttpMethod.Get, ManagementPath, _fx.ManagementToken,
            BuildProof(ec, "GET", Url(ManagementPath), _fx.ManagementToken));

        var resp = await _fx.Http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized, await resp.Content.ReadAsStringAsync());
    }

    // ─── helpers ───

    private static ECDsa NewKey() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

    /// <summary>RFC 9449 §7.1: the 401 names the DPoP scheme and carries the error.</summary>
    private static void AssertDpopChallenge(HttpResponseMessage resp)
    {
        var challenge = resp.Headers.WwwAuthenticate.Select(h => h.ToString()).ToArray();
        challenge.Should().ContainSingle(h => h.StartsWith("DPoP ", StringComparison.Ordinal), string.Join(" | ", challenge));
        challenge.Single(h => h.StartsWith("DPoP ", StringComparison.Ordinal)).Should().Contain("error=\"invalid_token\"");
    }

    private string Url(string path) => $"{_fx.BaseUrl.TrimEnd('/')}{path}";

    private static HttpRequestMessage DpopRequest(HttpMethod method, string path, string token, string proof)
    {
        var req = new HttpRequestMessage(method, path);
        req.Headers.TryAddWithoutValidation("Authorization", $"DPoP {token}");
        req.Headers.Add("DPoP", proof);
        return req;
    }

    /// <summary>Password grant for the confidential test client; DPoP-bound when <paramref name="dpopKey"/> is given.</summary>
    private async Task<string> PasswordTokenAsync(ECDsa? dpopKey)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
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
        if (dpopKey is not null)
            req.Headers.Add("DPoP", BuildProof(dpopKey, "POST", Url("/connect/token"), accessToken: null));
        return await ReadAccessTokenAsync(req, expectedType: dpopKey is null ? "Bearer" : "DPoP");
    }

    /// <summary>client_credentials token with the management scope, bound to <paramref name="dpopKey"/>.</summary>
    private async Task<string> ManagementTokenAsync(ECDsa dpopKey)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = ProductionHttpFixture.TestMgmtClientId,
                ["client_secret"] = ProductionHttpFixture.TestMgmtSecret,
                ["scope"] = "identity:manage"
            })
        };
        req.Headers.Add("DPoP", BuildProof(dpopKey, "POST", Url("/connect/token"), accessToken: null));
        return await ReadAccessTokenAsync(req, expectedType: "DPoP");
    }

    private async Task<string> ReadAccessTokenAsync(HttpRequestMessage req, string expectedType)
    {
        var resp = await _fx.Http.SendAsync(req);
        var body = await resp.Content.ReadAsStringAsync();
        resp.StatusCode.Should().Be(HttpStatusCode.OK, body);
        var json = JsonDocument.Parse(body).RootElement;
        json.GetProperty("token_type").GetString().Should().Be(expectedType, body);
        return json.GetProperty("access_token").GetString()!;
    }

    /// <summary>ES256 DPoP proof (RFC 9449 §4.2); <c>ath</c> is the SHA-256 of <paramref name="accessToken"/> when given.</summary>
    private static string BuildProof(ECDsa ec, string method, string url, string? accessToken, DateTimeOffset? issuedAt = null)
    {
        var pub = ec.ExportParameters(includePrivateParameters: false);
        var x = Base64UrlEncoder.Encode(pub.Q.X!);
        var y = Base64UrlEncoder.Encode(pub.Q.Y!);
        var headerJson = $"{{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}}}";

        var iat = (issuedAt ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds();
        var jti = Guid.NewGuid().ToString("N");
        var ath = accessToken is null
            ? string.Empty
            : $",\"ath\":\"{Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)))}\"";
        var payloadJson = $"{{\"htm\":\"{method}\",\"htu\":\"{url}\",\"iat\":{iat},\"jti\":\"{jti}\"{ath}}}";

        var signingInput = $"{Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(headerJson))}.{Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payloadJson))}";
        var sig = ec.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256);
        return $"{signingInput}.{Base64UrlEncoder.Encode(sig)}";
    }
}
