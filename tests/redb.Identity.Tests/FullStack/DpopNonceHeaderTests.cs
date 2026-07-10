using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// Z4 P2.2 E2E: validates RFC 9449 §8 DPoP-Nonce response-header emission.
/// On a successful DPoP-bearing token request the AS rotates the nonce via the
/// <c>DPoP-Nonce</c> response header so clients can adopt it for subsequent proofs.
/// </summary>
[Collection("ProductionHttp")]
public class DpopNonceHeaderTests
{
    private readonly ProductionHttpFixture _fx;

    public DpopNonceHeaderTests(ProductionHttpFixture fx) => _fx = fx;

    [Fact]
    public async Task Token_Endpoint_Emits_DPoP_Nonce_On_Successful_Exchange()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var (code, verifier) = await ObtainAuthCodeAsync();

        var url = $"{_fx.BaseUrl.TrimEnd('/')}/connect/token";
        var proof = BuildDpopProof(ec, "POST", url);

        using var req = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
                ["client_id"] = ProductionHttpFixture.TestPublicClientId,
                ["code_verifier"] = verifier
            })
        };
        req.Headers.Add("DPoP", proof);

        var resp = await _fx.Http.SendAsync(req);
        var body = await resp.Content.ReadAsStringAsync();
        resp.StatusCode.Should().Be(HttpStatusCode.OK, "DPoP exchange must succeed: {0}", body);

        var json = JsonDocument.Parse(body).RootElement;
        json.GetProperty("token_type").GetString().Should().Be("DPoP");

        var hasHeader = resp.Headers.TryGetValues("DPoP-Nonce", out var values)
                        || (resp.Content?.Headers?.TryGetValues("DPoP-Nonce", out values) ?? false);
        var allHeaders = string.Join("; ",
            resp.Headers.Select(h => $"{h.Key}=[{string.Join(",", h.Value)}]"));
        hasHeader.Should().BeTrue(
            "RFC 9449 §8: AS must rotate DPoP-Nonce on every DPoP-bearing response. Headers: {0}",
            allHeaders);
        var nonce = values!.First();
        nonce.Should().NotBeNullOrWhiteSpace();
        nonce.Length.Should().BeGreaterThan(40, "56 raw bytes ≈ 75 base64url chars");
    }

    private async Task<(string code, string verifier)> ObtainAuthCodeAsync()
    {
        var cookies = new CookieContainer();
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            CookieContainer = cookies,
            UseCookies = true
        };
        using var browser = new HttpClient(handler) { BaseAddress = new Uri(_fx.BaseUrl) };

        await browser.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = ProductionHttpFixture.TestUsername,
            ["password"] = ProductionHttpFixture.TestPassword
        }));

        var verifier = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        var challenge = Base64UrlEncoder.Encode(
            SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

        var url = $"/connect/authorize?response_type=code" +
                  $"&client_id={Uri.EscapeDataString(ProductionHttpFixture.TestPublicClientId)}" +
                  $"&redirect_uri={Uri.EscapeDataString(ProductionHttpFixture.TestRedirectUri)}" +
                  $"&scope=openid&code_challenge={challenge}&code_challenge_method=S256&state=nonce-test";

        var resp = await browser.GetAsync(url);
        string? code;
        if (resp.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found)
        {
            var loc = resp.Headers.Location?.ToString() ?? "";
            var idx = loc.IndexOf("code=", StringComparison.Ordinal);
            code = idx >= 0
                ? Uri.UnescapeDataString(loc[(idx + 5)..].Split('&')[0])
                : null;
        }
        else
        {
            var bod = await resp.Content.ReadAsStringAsync();
            var doc = JsonDocument.Parse(bod).RootElement;
            code = doc.GetProperty("code").GetString();
        }
        code.Should().NotBeNullOrEmpty("authorize must produce a code");
        return (code!, verifier);
    }

    private static string BuildDpopProof(ECDsa ec, string method, string url)
    {
        var p = ec.ExportParameters(false);
        var x = Base64UrlEncoder.Encode(p.Q.X!);
        var y = Base64UrlEncoder.Encode(p.Q.Y!);
        var jwk = $"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}";
        var header = $"{{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":{jwk}}}";
        var iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var jti = Guid.NewGuid().ToString("N");
        var payload = $"{{\"htm\":\"{method}\",\"htu\":\"{url}\",\"iat\":{iat},\"jti\":\"{jti}\"}}";
        var hB64 = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header));
        var pB64 = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload));
        var input = $"{hB64}.{pB64}";
        var sig = ec.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256);
        return $"{input}.{Base64UrlEncoder.Encode(sig)}";
    }
}
