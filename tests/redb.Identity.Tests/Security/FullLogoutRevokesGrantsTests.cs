using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Security;

/// <summary>
/// What "sign this user out everywhere" ends. The operator's logout (<c>POST /api/v1/identity/sessions/logout</c>),
/// a password change, a password reset and a SCIM deactivation all go through
/// <c>SessionService.LogoutAsync</c>, whose contract is: every session revoked and every grant with it, so
/// no token issued to the user keeps working. Authorizations and tokens are keyed by the user's public
/// subject (<c>value_guid</c>) since V4, and a revocation that looked them up by the internal user id
/// found nothing: sessions ended, refresh tokens lived on. This pins the contract through the real path,
/// for a grant with an authorization row (authorization code) and one without (ROPC).
/// <para>
/// The other logout is the browser's own: signing out of one OP session (<c>/connect/logout</c>) ends that
/// session and notifies its relying parties, and leaves the user's grants alone. Refresh tokens exist only
/// with <c>offline_access</c>, which OIDC Core §11 defines as access while the End-User is not logged in,
/// so signing out of one browser must not sign the user's other applications out (Keycloak keeps offline
/// tokens across a session logout; Duende revokes nothing on logout). The second test pins that line.
/// </para>
/// </summary>
[Collection("ProductionHttp")]
public sealed class FullLogoutRevokesGrantsTests
{
    private readonly ProductionHttpFixture _fx;

    public FullLogoutRevokesGrantsTests(ProductionHttpFixture fx) => _fx = fx;

    [Fact]
    public async Task Signing_the_user_out_everywhere_ends_every_refresh_token()
    {
        var coreUser = await _fx.UseRedbAsync(redb => redb.UserProvider.GetUserByLoginAsync(ProductionHttpFixture.TestUsername));
        coreUser.Should().NotBeNull();

        using var browser = await LoginAsync();
        var codeGrantRefresh = await IssueRefreshTokenThroughBrowserAsync(browser);
        var ropcRefresh = await IssueRefreshTokenThroughPasswordGrantAsync();

        // Both grants work before the logout — the test is about what the logout ends, not about issuance.
        (await RefreshAsync(codeGrantRefresh, ProductionHttpFixture.TestPublicClientId, null)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await RefreshAsync(ropcRefresh, ProductionHttpFixture.TestClientId, ProductionHttpFixture.TestClientSecret)).StatusCode.Should().Be(HttpStatusCode.OK);
        // Rotation handed out new refresh tokens; re-issue so we hold live ones.
        codeGrantRefresh = await IssueRefreshTokenThroughBrowserAsync(browser);
        ropcRefresh = await IssueRefreshTokenThroughPasswordGrantAsync();

        var logout = new HttpRequestMessage(System.Net.Http.HttpMethod.Post, $"/api/v1/identity/sessions/logout?userId={coreUser!.Id}");
        logout.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fx.ManagementToken);
        var resp = await _fx.Http.SendAsync(logout);
        resp.StatusCode.Should().Be(HttpStatusCode.OK, "operator logout failed: {0}", await resp.Content.ReadAsStringAsync());

        var codeGrantAfter = await RefreshAsync(codeGrantRefresh, ProductionHttpFixture.TestPublicClientId, null);
        codeGrantAfter.IsSuccessStatusCode.Should().BeFalse(
            "a refresh token issued through the authorization code flow must die with the user's grants; got {0}: {1}",
            codeGrantAfter.StatusCode, await codeGrantAfter.Content.ReadAsStringAsync());

        var ropcAfter = await RefreshAsync(ropcRefresh, ProductionHttpFixture.TestClientId, ProductionHttpFixture.TestClientSecret);
        ropcAfter.IsSuccessStatusCode.Should().BeFalse(
            "a refresh token issued through the password grant has no authorization row and must be revoked on its own; got {0}: {1}",
            ropcAfter.StatusCode, await ropcAfter.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Signing_out_of_one_session_ends_that_session_and_keeps_offline_access_grants()
    {
        using var browser = await LoginAsync();
        var session = await NewestActiveSessionAsync();
        var refresh = await IssueRefreshTokenThroughBrowserAsync(browser);

        var done = await LogoutFlow.SignOutAsync(browser);
        ((int)done.StatusCode).Should().BeOneOf(200, 302);

        var ended = await _fx.UseRedbAsync(redb => redb.LoadAsync<redb.Identity.Core.Models.SessionProps>(session.id));
        ended!.Props.Status.Should().Be("revoked", "the browser's own OP session is what the logout ends");

        var after = await RefreshAsync(refresh, ProductionHttpFixture.TestPublicClientId, null);
        after.StatusCode.Should().Be(HttpStatusCode.OK,
            "offline_access is access while the End-User is not logged in; a session logout does not revoke it: {0}",
            await after.Content.ReadAsStringAsync());
    }

    // ── helpers ──

    /// <summary>Tests in this collection run one at a time, so the newest active session is the one just created.</summary>
    private async Task<redb.Core.Models.Entities.RedbObject<redb.Identity.Core.Models.SessionProps>> NewestActiveSessionAsync()
    {
        var active = await _fx.UseRedbAsync(redb => redb.Query<redb.Identity.Core.Models.SessionProps>()
            .Where(s => s.Status == "active")
            .ToListAsync());
        return active.OrderByDescending(s => s.id).First();
    }

    private async Task<HttpClient> LoginAsync()
    {
        var jar = new CookieContainer();
        var client = new HttpClient(new HttpClientHandler
        {
            AllowAutoRedirect = false,
            CookieContainer = jar,
            UseCookies = true,
        })
        { BaseAddress = new Uri(_fx.BaseUrl) };

        var login = await client.PostAsync("/login", Form(new()
        {
            ["username"] = ProductionHttpFixture.TestUsername,
            ["password"] = ProductionHttpFixture.TestPassword,
        }));
        ((int)login.StatusCode).Should().BeOneOf(200, 302);
        jar.Count.Should().BeGreaterThan(0, "login must issue the session cookie");
        return client;
    }

    private async Task<string> IssueRefreshTokenThroughBrowserAsync(HttpClient browser)
    {
        var (verifier, challenge) = Pkce();
        var authorize = await browser.PostAsync("/connect/authorize", Form(new()
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionHttpFixture.TestPublicClientId,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
            ["scope"] = "openid offline_access",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
        }));

        string? code = null;
        if (authorize.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found)
            code = QueryParam(authorize.Headers.Location!.ToString(), "code");
        else if (JsonDocument.Parse(await authorize.Content.ReadAsStringAsync()).RootElement.TryGetProperty("code", out var c))
            code = c.GetString();
        code.Should().NotBeNullOrEmpty("authorize must yield a code for the logged-in browser");

        var token = await _fx.Http.PostAsync("/connect/token", Form(new()
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code!,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
            ["client_id"] = ProductionHttpFixture.TestPublicClientId,
            ["code_verifier"] = verifier,
        }));
        token.StatusCode.Should().Be(HttpStatusCode.OK, "token exchange failed: {0}", await token.Content.ReadAsStringAsync());
        return JsonDocument.Parse(await token.Content.ReadAsStringAsync()).RootElement.GetProperty("refresh_token").GetString()!;
    }

    private async Task<string> IssueRefreshTokenThroughPasswordGrantAsync()
    {
        var resp = await _fx.Http.PostAsync("/connect/token", Form(new()
        {
            ["grant_type"] = "password",
            ["username"] = ProductionHttpFixture.TestUsername,
            ["password"] = ProductionHttpFixture.TestPassword,
            ["client_id"] = ProductionHttpFixture.TestClientId,
            ["client_secret"] = ProductionHttpFixture.TestClientSecret,
            ["scope"] = "openid offline_access",
        }));
        resp.StatusCode.Should().Be(HttpStatusCode.OK, "password grant failed: {0}", await resp.Content.ReadAsStringAsync());
        return JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement.GetProperty("refresh_token").GetString()!;
    }

    private Task<HttpResponseMessage> RefreshAsync(string refreshToken, string clientId, string? clientSecret)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
            ["client_id"] = clientId,
        };
        if (clientSecret is not null) form["client_secret"] = clientSecret;
        return _fx.Http.PostAsync("/connect/token", Form(form));
    }

    private static FormUrlEncodedContent Form(Dictionary<string, string> kv) => new(kv);

    private static (string verifier, string challenge) Pkce()
    {
        var bytes = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        var verifier = Base64Url(bytes);
        var challenge = Base64Url(System.Security.Cryptography.SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        return (verifier, challenge);
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string? QueryParam(string url, string name)
    {
        var idx = url.IndexOf('?');
        if (idx < 0) return null;
        foreach (var pair in url[(idx + 1)..].Split('&'))
        {
            var kv = pair.Split('=', 2);
            if (kv[0] == name) return Uri.UnescapeDataString(kv[1]);
        }
        return null;
    }
}
