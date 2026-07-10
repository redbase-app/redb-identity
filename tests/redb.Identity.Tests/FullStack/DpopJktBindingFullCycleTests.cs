using System.Net;
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
/// Z4 P2.1 E2E: end-to-end full-cycle test for the <c>dpop_jkt</c> binding at the
/// authorization endpoint (RFC 9449 §10).
///
/// Pipeline:
///   /login → GET /connect/authorize?dpop_jkt=… → callback (code) → POST /connect/token (with DPoP proof)
///
/// Scenarios:
/// 1. Match: same EC key used for both <c>dpop_jkt</c> and the proof at /token → access_token issued (token_type=DPoP).
/// 2. Mismatch: /token DPoP proof comes from a different key → invalid_grant.
/// 3. Missing proof: code bound to <c>dpop_jkt</c> but no DPoP header at /token → invalid_grant.
/// </summary>
[Collection("ProductionHttp")]
public class DpopJktBindingFullCycleTests
{
    private readonly ProductionHttpFixture _fx;

    public DpopJktBindingFullCycleTests(ProductionHttpFixture fx) => _fx = fx;

    [Fact]
    public async Task Authorize_With_DpopJkt_Then_Token_With_Matching_Proof_Succeeds()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jkt = ComputeJkt(ec);
        var (code, verifier) = await ObtainAuthCodeWithDpopJktAsync(jkt);

        var url = $"{_fx.BaseUrl.TrimEnd('/')}/connect/token";
        var proof = BuildDpopProof(ec, "POST", url);
        using var req = BuildTokenRequest(code, verifier);
        req.Headers.Add("DPoP", proof);

        var resp = await _fx.Http.SendAsync(req);
        var body = await resp.Content.ReadAsStringAsync();
        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            "code bound to dpop_jkt must redeem when proof matches: {0}", body);

        var json = JsonDocument.Parse(body).RootElement;
        json.GetProperty("token_type").GetString().Should().Be("DPoP");
        var at = json.GetProperty("access_token").GetString()!;
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(at);
        jwt.TryGetPayloadValue<JsonElement>("cnf", out var cnf).Should().BeTrue();
        cnf.GetProperty("jkt").GetString().Should().Be(jkt);
    }

    [Fact]
    public async Task Authorize_With_DpopJkt_Then_Token_With_Mismatched_Proof_Returns_InvalidGrant()
    {
        using var ecAuthorize = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ecToken = ECDsa.Create(ECCurve.NamedCurves.nistP256); // different key
        var jkt = ComputeJkt(ecAuthorize);
        var (code, verifier) = await ObtainAuthCodeWithDpopJktAsync(jkt);

        var url = $"{_fx.BaseUrl.TrimEnd('/')}/connect/token";
        var proof = BuildDpopProof(ecToken, "POST", url);
        using var req = BuildTokenRequest(code, verifier);
        req.Headers.Add("DPoP", proof);

        var resp = await _fx.Http.SendAsync(req);
        ((int)resp.StatusCode).Should().BeGreaterOrEqualTo(400,
            "RFC 9449 §10.1: token must be refused when proof's jkt differs from the bound dpop_jkt");
        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        body.GetProperty("error").GetString().Should().Be("invalid_grant");
    }

    [Fact]
    public async Task Authorize_With_DpopJkt_Then_Token_Without_Proof_Returns_InvalidGrant()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jkt = ComputeJkt(ec);
        var (code, verifier) = await ObtainAuthCodeWithDpopJktAsync(jkt);

        using var req = BuildTokenRequest(code, verifier); // no DPoP header

        var resp = await _fx.Http.SendAsync(req);
        ((int)resp.StatusCode).Should().BeGreaterOrEqualTo(400);
        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        body.GetProperty("error").GetString().Should().Be("invalid_grant");
    }

    [Fact]
    public async Task Authorize_With_Malformed_DpopJkt_Returns_InvalidRequest()
    {
        var cookies = new CookieContainer();
        using var browser = BuildBrowser(cookies);
        await LoginAsync(browser);

        var (verifier, challenge) = GeneratePkce();
        var malformedJkt = "not-a-real-jkt!!"; // fails IsWellFormedJkt
        var url = BuildAuthorizeUrl(verifier: null, challenge, dpopJkt: malformedJkt, state: "x");
        _ = verifier;
        var resp = await browser.GetAsync(url);

        // Authorize handler returns invalid_request either as a redirect or as a 400 page.
        if (resp.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found)
        {
            var loc = resp.Headers.Location?.ToString() ?? "";
            loc.Should().Contain("error=invalid_request", "malformed dpop_jkt must produce invalid_request");
        }
        else
        {
            ((int)resp.StatusCode).Should().BeGreaterOrEqualTo(400);
        }
    }

    // ─── Pipeline helpers ───

    private async Task<(string code, string verifier)> ObtainAuthCodeWithDpopJktAsync(string jkt)
    {
        var cookies = new CookieContainer();
        using var browser = BuildBrowser(cookies);
        await LoginAsync(browser);

        var (verifier, challenge) = GeneratePkce();
        var url = BuildAuthorizeUrl(null, challenge, dpopJkt: jkt, state: "dpopjkt-state");
        var resp = await browser.GetAsync(url);

        // Authorize may either redirect to redirect_uri (302/Found) or, in this server's
        // configuration, return 200 OK with a JSON body containing the code (PAR-style).
        string? code;
        if (resp.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found)
        {
            var location = resp.Headers.Location?.ToString();
            location.Should().NotBeNullOrEmpty();
            location!.Should().StartWith(ProductionHttpFixture.TestRedirectUri);
            code = ExtractQueryParam(location, "code");
        }
        else
        {
            resp.StatusCode.Should().Be(HttpStatusCode.OK,
                "authorize must produce a code: {0}", await resp.Content.ReadAsStringAsync());
            var body = await resp.Content.ReadAsStringAsync();
            var json = JsonDocument.Parse(body).RootElement;
            json.TryGetProperty("code", out var c).Should().BeTrue("authorize JSON body must contain code");
            code = c.GetString();
        }
        code.Should().NotBeNullOrEmpty("authorize must produce a code");
        return (code!, verifier);
    }

    private HttpClient BuildBrowser(CookieContainer cookies)
    {
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            CookieContainer = cookies,
            UseCookies = true
        };
        return new HttpClient(handler) { BaseAddress = new Uri(_fx.BaseUrl) };
    }

    private static async Task LoginAsync(HttpClient browser)
    {
        var loginForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = ProductionHttpFixture.TestUsername,
            ["password"] = ProductionHttpFixture.TestPassword
        });
        await browser.PostAsync("/login", loginForm);
    }

    private static string BuildAuthorizeUrl(string? verifier, string challenge, string dpopJkt, string state)
    {
        _ = verifier;
        return $"/connect/authorize?response_type=code" +
               $"&client_id={Uri.EscapeDataString(ProductionHttpFixture.TestPublicClientId)}" +
               $"&redirect_uri={Uri.EscapeDataString(ProductionHttpFixture.TestRedirectUri)}" +
               $"&scope=openid" +
               $"&code_challenge={challenge}&code_challenge_method=S256" +
               $"&state={state}" +
               $"&dpop_jkt={Uri.EscapeDataString(dpopJkt)}";
    }

    private static HttpRequestMessage BuildTokenRequest(string code, string verifier) =>
        new(HttpMethod.Post, "/connect/token")
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

    private static string? ExtractQueryParam(string url, string param)
    {
        var idx = url.IndexOf('?');
        if (idx < 0) return null;
        var query = url[(idx + 1)..];
        var hashIdx = query.IndexOf('#');
        if (hashIdx >= 0) query = query[..hashIdx];
        foreach (var pair in query.Split('&'))
        {
            var kv = pair.Split('=', 2);
            if (kv.Length == 2 && kv[0] == param)
                return Uri.UnescapeDataString(kv[1]);
        }
        return null;
    }

    private static (string verifier, string challenge) GeneratePkce()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        var verifier = Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        var challenge = Convert.ToBase64String(hash).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return (verifier, challenge);
    }

    // ─── DPoP helpers (same as DpopFullCycleTests) ───

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

    private static string ComputeJkt(ECDsa ec)
    {
        var p = ec.ExportParameters(false);
        var x = Base64UrlEncoder.Encode(p.Q.X!);
        var y = Base64UrlEncoder.Encode(p.Q.Y!);
        var canonical = $"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}";
        return Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }
}
