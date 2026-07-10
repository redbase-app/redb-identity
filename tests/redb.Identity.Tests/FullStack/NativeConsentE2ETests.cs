using System.Net;
using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// Sessions B-2 + B-3 (N-2 Native Consent) — end-to-end coverage of:
///  • the <c>X-Identity-Delegate-Consent</c> header content-negotiation on
///    <c>/connect/authorize</c> (B-2);
///  • the full <c>authorize → consent_required → POST /consent → resume
///    authorize → POST /connect/token</c> happy-path (B-3), exercising the
///    same host-side <c>/consent</c> form endpoint that
///    <c>BackchannelOidcClient.RecordConsentGrantAsync</c> calls in production.
///
/// All tests run against the real OpenIddict pipeline + redb-backed stores +
/// real PostgreSQL via <see cref="ProductionHttpFixture"/>.
/// </summary>
[Collection("ProductionHttp")]
public sealed class NativeConsentE2ETests : IAsyncLifetime
{
    private const string ConsentClientId = ProductionHttpFixture.TestConsentClientId;
    private readonly ProductionHttpFixture _fx;

    public NativeConsentE2ETests(ProductionHttpFixture fx) { _fx = fx; }

    /// <summary>
    /// Tests share a fixture, and the happy-path test creates an OpenIddict
    /// Authorization row that — if it survives between tests — silences the
    /// consent gate that the header-negotiation tests rely on. We delete any
    /// pre-existing authorization for the test client at the start of every
    /// test so order does not matter.
    /// </summary>
    public async Task InitializeAsync()
    {
        var appManager = _fx.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var authManager = _fx.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationManager>();

        var app = await appManager.FindByClientIdAsync(ConsentClientId);
        if (app is null) return;
        var appId = await appManager.GetIdAsync(app);
        if (appId is null) return;

        // Delete every authorization tied to this client, regardless of subject.
        // Subject linkage on AuthorizationProps now lives in value_guid (the public sub
        // GUID); enumerating by application id alone sidesteps any lookup-by-subject
        // edge case and keeps the cleanup robust for header-negotiation tests.
        await foreach (var auth in authManager.FindByApplicationIdAsync(appId))
        {
            await authManager.TryRevokeAsync(auth);
            await authManager.DeleteAsync(auth);
        }
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task AuthorizeWithDelegateHeader_ReturnsConsentRequiredJson()
    {
        var (cookieJar, client) = await NewLoggedInClient();

        var resp = await PostAuthorize(client, delegateHeader: "1");

        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest,
            "delegate header must short-circuit the legacy 302 to /consent and return a machine-readable error instead. Body: {0}",
            await resp.Content.ReadAsStringAsync());
        resp.Content.Headers.ContentType?.MediaType.Should().Be("application/json");

        var json = await ParseJsonAsync(resp);
        json.GetProperty("error").GetString().Should().Be("consent_required");
        json.GetProperty("clientId").GetString().Should().Be(ConsentClientId);
        json.GetProperty("appName").GetString().Should().NotBeNullOrEmpty();
        json.GetProperty("scopes").GetArrayLength().Should().BeGreaterThan(0);
        json.GetProperty("userId").GetString().Should().NotBeNullOrEmpty();
        json.GetProperty("returnUrl").GetString().Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task AuthorizeWithDelegateHeaderTrueLiteral_AlsoReturnsJson()
    {
        var (_, client) = await NewLoggedInClient();

        var resp = await PostAuthorize(client, delegateHeader: "True");

        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest,
            "the header value matcher must accept both \"1\" and \"true\" — case-insensitive. Body: {0}",
            await resp.Content.ReadAsStringAsync());
        resp.Content.Headers.ContentType?.MediaType.Should().Be("application/json");
    }

    [Fact]
    public async Task AuthorizeWithoutDelegateHeader_StillReturnsLegacyConsentRedirect()
    {
        var (_, client) = await NewLoggedInClient();

        var resp = await PostAuthorize(client, delegateHeader: null);

        // Legacy behaviour: 302 to the host's /consent HTML page. We do not pin
        // the exact target (host may render inline or redirect) — only that we
        // did NOT get the new JSON shape. Status must be either a redirect or
        // a 200 (host rendered the consent page inline); anything else means
        // the delegate-header branch leaked into the no-header path.
        ((int)resp.StatusCode).Should().BeOneOf(new[] { 200, 302, 303 },
            "without the delegate header, native JSON branch must NOT activate. Got {0}: {1}",
            resp.StatusCode, await resp.Content.ReadAsStringAsync());

        if (resp.StatusCode is HttpStatusCode.OK)
        {
            // Inline-rendered host consent page is HTML, not JSON.
            resp.Content.Headers.ContentType?.MediaType.Should().NotBe("application/json");
        }
    }

    [Fact]
    public async Task HappyPath_AuthorizeThenGrantConsentThenResumeThenToken_YieldsAccessAndIdToken()
    {
        // ─── Step 1: log in (session cookie) ───
        var (_, client) = await NewLoggedInClient();

        // ─── Step 2: GET /connect/authorize with delegate header → 400 JSON consent_required ───
        // Use GET (not POST) because the host reconstructs returnUrl from the request
        // line, and our resume step needs that returnUrl to carry the original PKCE +
        // OIDC params. This is exactly what BackchannelOidcClient does in production.
        var (verifier, challenge) = GeneratePkce();
        var state = "b3-happy-state";
        var nonce = "b3-happy-nonce";
        var authorizeQuery =
            $"response_type=code"
            + $"&client_id={Uri.EscapeDataString(ConsentClientId)}"
            + $"&redirect_uri={Uri.EscapeDataString(ProductionHttpFixture.TestRedirectUri)}"
            + $"&scope={Uri.EscapeDataString("openid profile")}"
            + $"&state={state}"
            + $"&nonce={nonce}"
            + $"&code_challenge={challenge}"
            + $"&code_challenge_method=S256";

        using (var consentReq = new HttpRequestMessage(HttpMethod.Get, "/connect/authorize?" + authorizeQuery))
        {
            consentReq.Headers.Add("X-Identity-Delegate-Consent", "1");
            var consentResp = await client.SendAsync(consentReq);

            consentResp.StatusCode.Should().Be(HttpStatusCode.BadRequest,
                "expected consent_required JSON, got body: {0}",
                await consentResp.Content.ReadAsStringAsync());

            var json = await ParseJsonAsync(consentResp);
            json.GetProperty("error").GetString().Should().Be("consent_required");

            var returnUrl = json.GetProperty("returnUrl").GetString();
            returnUrl.Should().NotBeNullOrEmpty();
            returnUrl!.Should().StartWith("/connect/authorize?");

            var scopes = string.Join(' ',
                json.GetProperty("scopes").EnumerateArray().Select(s => s.GetString()));

            // ─── Step 3: POST /consent (decision=allow) — mirrors RecordConsentGrantAsync ───
            // Host records the authorization (creates Authorization row) and responds
            // with a 302 to returnUrl on success.
            var consentForm = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = ConsentClientId,
                ["scopes"] = scopes,
                ["decision"] = "allow",
                ["returnUrl"] = returnUrl,
            });
            var grantResp = await client.PostAsync("/consent", consentForm);

            grantResp.StatusCode.Should().BeOneOf(
                new[] { HttpStatusCode.Found, HttpStatusCode.SeeOther },
                "host /consent allow must respond with a redirect to returnUrl. Body: {0}",
                await grantResp.Content.ReadAsStringAsync());
            grantResp.Headers.Location?.ToString().Should().NotBeNull();
        }

        // ─── Step 4: GET /connect/authorize again (no header) → 302 to redirect_uri?code=… ───
        // Authorization row now exists, so OpenIddict skips the consent gate and issues a code.
        string? code;
        string? echoedState;
        using (var resumeReq = new HttpRequestMessage(HttpMethod.Get, "/connect/authorize?" + authorizeQuery))
        {
            var resumeResp = await client.SendAsync(resumeReq);
            resumeResp.StatusCode.Should().BeOneOf(
                new[] { HttpStatusCode.Found, HttpStatusCode.SeeOther },
                "after consent grant, replay of authorize must redirect to redirect_uri with ?code=… . Body: {0}",
                await resumeResp.Content.ReadAsStringAsync());

            var location = resumeResp.Headers.Location?.ToString();
            location.Should().NotBeNull();
            location!.Should().StartWith(ProductionHttpFixture.TestRedirectUri);
            code = ExtractQueryParam(location, "code");
            echoedState = ExtractQueryParam(location, "state");
            code.Should().NotBeNullOrEmpty("authorize replay must produce a code");
            echoedState.Should().Be(state, "state must round-trip unchanged through consent + resume");
        }

        // ─── Step 5: POST /connect/token (code + verifier) → access + id token ───
        var tokenForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code!,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
            ["client_id"] = ConsentClientId,
            ["code_verifier"] = verifier,
        });
        var tokenResp = await _fx.Http.PostAsync("/connect/token", tokenForm);
        tokenResp.StatusCode.Should().Be(HttpStatusCode.OK,
            "token exchange after consent grant must succeed: {0}",
            await tokenResp.Content.ReadAsStringAsync());

        var tokenJson = await ParseJsonAsync(tokenResp);
        tokenJson.GetProperty("access_token").GetString().Should().NotBeNullOrEmpty();
        tokenJson.GetProperty("id_token").GetString().Should().NotBeNullOrEmpty();
        tokenJson.GetProperty("token_type").GetString().Should().Be("Bearer");
    }

    // ────────────────── helpers ──────────────────

    private async Task<(CookieContainer cookies, HttpClient client)> NewLoggedInClient()
    {
        var cookies = new CookieContainer();
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            CookieContainer = cookies,
            UseCookies = true,
        };
        var client = new HttpClient(handler) { BaseAddress = new Uri(_fx.BaseUrl) };

        var loginResp = await client.PostAsync("/login", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["username"] = ProductionHttpFixture.TestUsername,
                ["password"] = ProductionHttpFixture.TestPassword,
            }));
        // The /login response must set a session cookie regardless of whether
        // it returns 200 (rendered "logged in" page) or 302 (redirect to next).
        cookies.Count.Should().BeGreaterThan(0,
            "login must set the session cookie; got {0}", loginResp.StatusCode);

        return (cookies, client);
    }

    private static async Task<HttpResponseMessage> PostAuthorize(
        HttpClient client, string? delegateHeader)
    {
        var (_, challenge) = GeneratePkce();
        var form = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ConsentClientId,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
            ["scope"] = "openid profile",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
        };
        using var req = new HttpRequestMessage(HttpMethod.Post, "/connect/authorize")
        {
            Content = new FormUrlEncodedContent(form)
        };
        if (delegateHeader is not null)
            req.Headers.Add("X-Identity-Delegate-Consent", delegateHeader);
        return await client.SendAsync(req);
    }

    private static async Task<JsonElement> ParseJsonAsync(HttpResponseMessage resp)
    {
        var body = await resp.Content.ReadAsStringAsync();
        return JsonDocument.Parse(body).RootElement;
    }

    private static (string verifier, string challenge) GeneratePkce()
    {
        var bytes = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        var verifier = Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var hash = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(verifier));
        var challenge = Convert.ToBase64String(hash).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return (verifier, challenge);
    }

    private static string? ExtractQueryParam(string url, string key)
    {
        var qIdx = url.IndexOf('?');
        if (qIdx < 0) return null;
        foreach (var pair in url[(qIdx + 1)..].Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = pair.IndexOf('=');
            if (eq <= 0) continue;
            if (Uri.UnescapeDataString(pair[..eq]) == key)
                return Uri.UnescapeDataString(pair[(eq + 1)..]);
        }
        return null;
    }
}
