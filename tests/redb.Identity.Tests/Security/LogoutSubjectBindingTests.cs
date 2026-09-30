using System.Net;
using System.Text.Json;
using FluentAssertions;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Security;

/// <summary>
/// Whom a logout acts upon. <c>/connect/logout</c> is the OIDC <c>end_session_endpoint</c>: relying parties
/// send the browser there, so it cannot demand authentication of its own. Its subject is therefore the
/// browser's OP session — the cookie the request carries — and nothing the request says about the user.
/// <para>
/// The processor used to read a <c>userId</c> from the form (the GET variant maps the query string the same
/// way) and, when the cookie was absent, sign that user out of every session, revoke the user's
/// authorizations and notify every relying party over the back channel. The value was the caller's word.
/// These tests pin that a request without the session cookie ends no session whatever it names, that a
/// bare <c>id_token_hint</c> is completed rather than refused (RP-Initiated Logout 1.0 §2 — the redirect
/// back to the RP still has to happen), and that the browser holding the cookie still ends its own session.
/// </para>
/// </summary>
[Collection("ProductionHttp")]
public sealed class LogoutSubjectBindingTests
{
    private readonly ProductionHttpFixture _fx;

    public LogoutSubjectBindingTests(ProductionHttpFixture fx) => _fx = fx;

    [Fact]
    public async Task A_request_without_the_session_cookie_ends_no_session_whatever_user_it_names()
    {
        using var browser = await LoginAsync();
        var session = await NewestActiveSessionAsync();
        var userId = session.key!.Value;

        using var stranger = AnonymousClient();

        var post = await stranger.PostAsync("/connect/logout", Form(new() { ["userId"] = userId.ToString() }));
        ((int)post.StatusCode).Should().BeLessThan(500);
        (await SessionStatusAsync(session.id)).Should().Be("active",
            "a form field does not choose whom to sign out; only the session cookie does");

        var get = await stranger.GetAsync($"/connect/logout?userId={userId}");
        ((int)get.StatusCode).Should().BeLessThan(500);
        (await SessionStatusAsync(session.id)).Should().Be("active", "nor does a query parameter");

        // Control: the browser holding the cookie still ends its own session (through the confirmation page,
        // since it presents no id_token_hint).
        var own = await LogoutFlow.ConfirmAsync(browser, await browser.PostAsync("/connect/logout", Form(new())));
        ((int)own.StatusCode).Should().BeOneOf(200, 302);
        (await SessionStatusAsync(session.id)).Should().Be("revoked");
    }

    [Fact]
    public async Task An_id_token_hint_alone_completes_the_request_and_ends_no_session()
    {
        using var browser = await LoginAsync();
        var session = await NewestActiveSessionAsync();
        var idToken = await IssueIdTokenAsync(browser);

        using var stranger = AnonymousClient();
        var resp = await stranger.PostAsync("/connect/logout", Form(new() { ["id_token_hint"] = idToken }));
        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            "RP-Initiated Logout 1.0 §2: a browser with no OP session is not an error, the OP completes the request; body: {0}",
            await resp.Content.ReadAsStringAsync());
        (await SessionStatusAsync(session.id)).Should().Be("active",
            "the hint names the user; the request does not come from that user's browser");

        await LogoutFlow.SignOutAsync(browser);
    }

    // ── helpers ──

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

    private HttpClient AnonymousClient() =>
        new(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false })
        { BaseAddress = new Uri(_fx.BaseUrl) };

    /// <summary>Tests in this collection run one at a time, so the newest active session is the one just created.</summary>
    private async Task<RedbObject<SessionProps>> NewestActiveSessionAsync()
    {
        var active = await _fx.UseRedbAsync(redb => redb.Query<SessionProps>()
            .Where(s => s.Status == "active")
            .ToListAsync());
        return active.OrderByDescending(s => s.id).First();
    }

    private async Task<string?> SessionStatusAsync(long sessionId)
    {
        var session = await _fx.UseRedbAsync(redb => redb.LoadAsync<SessionProps>(sessionId));
        return session!.Props.Status;
    }

    /// <summary>Authorization code flow with the browser's own cookie: the id_token names the logged-in user.</summary>
    private async Task<string> IssueIdTokenAsync(HttpClient browser)
    {
        var (verifier, challenge) = Pkce();
        var authorize = await browser.PostAsync("/connect/authorize", Form(new()
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionHttpFixture.TestPublicClientId,
            ["redirect_uri"] = ProductionHttpFixture.TestRedirectUri,
            ["scope"] = "openid",
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
        return JsonDocument.Parse(await token.Content.ReadAsStringAsync()).RootElement.GetProperty("id_token").GetString()!;
    }

    private static FormUrlEncodedContent Form(Dictionary<string, string> kv) => new(kv);

    private static (string verifier, string challenge) Pkce()
    {
        var bytes = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        var verifier = Base64Url(bytes);
        var challenge = Base64Url(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(verifier)));
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
