using System.Net;
using FluentAssertions;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Security;

/// <summary>
/// Whether the End-User asked to sign out. The session cookie travels with a cross-site top-level
/// navigation (<c>SameSite=Lax</c>), so a link on any page could send the browser to
/// <c>/connect/logout</c>; the cookie proves whose session it is, not that its owner wants it ended. A
/// relying party proves intent with a valid <c>id_token_hint</c> for the session's user (covered by the
/// back-channel test); without one the OP shows a confirmation page whose form carries a state bound to
/// this user and session, and only that state, posted back, ends the session. Duende's logout prompt and
/// Keycloak's confirmation without <c>id_token_hint</c> behave the same way.
/// </summary>
[Collection("ProductionHttp")]
public sealed class LogoutConfirmationTests
{
    private readonly ProductionHttpFixture _fx;

    public LogoutConfirmationTests(ProductionHttpFixture fx) => _fx = fx;

    [Fact]
    public async Task Without_a_hint_the_browser_is_asked_first_and_nothing_ends()
    {
        var (browser, jar) = await LoginAsync();
        var session = await NewestActiveSessionAsync();

        var get = await browser.GetAsync("/connect/logout");
        get.StatusCode.Should().Be(HttpStatusCode.OK);
        LogoutFlow.IsConfirmationPage(await get.Content.ReadAsStringAsync()).Should().BeTrue("a GET without id_token_hint is a link, not a decision");
        (await SessionStatusAsync(session.id)).Should().Be("active");
        HasSessionCookie(jar).Should().BeTrue("the page must not clear the cookie it is asking about");

        var post = await browser.PostAsync("/connect/logout", Form(new()));
        post.StatusCode.Should().Be(HttpStatusCode.OK);
        LogoutFlow.IsConfirmationPage(await post.Content.ReadAsStringAsync()).Should().BeTrue("a bare POST proves no more than a GET");
        (await SessionStatusAsync(session.id)).Should().Be("active");

        await LogoutFlow.ConfirmAsync(browser, post);
    }

    [Fact]
    public async Task Confirming_with_the_pages_state_ends_the_session()
    {
        var (browser, jar) = await LoginAsync();
        var session = await NewestActiveSessionAsync();

        var page = await browser.GetAsync("/connect/logout");
        var done = await LogoutFlow.ConfirmAsync(browser, page);

        done.StatusCode.Should().Be(HttpStatusCode.OK);
        (await done.Content.ReadAsStringAsync()).Should().Contain("Signed Out");
        (await SessionStatusAsync(session.id)).Should().Be("revoked");
        HasSessionCookie(jar).Should().BeFalse("the confirmed logout clears the session cookie");
    }

    [Fact]
    public async Task A_state_that_is_not_ours_or_belongs_to_another_session_does_not_confirm()
    {
        var (alice, _) = await LoginAsync();
        var aliceSession = await NewestActiveSessionAsync();
        var (bob, _) = await LoginAsync();
        var bobSession = await NewestActiveSessionAsync();
        bobSession.id.Should().NotBe(aliceSession.id);

        var alicePage = LogoutFlow.HiddenFields(await (await alice.GetAsync("/connect/logout")).Content.ReadAsStringAsync());
        alicePage.Should().ContainKey("logout_state");

        // Another session's state: bound to alice, useless in bob's browser.
        var bobWithAliceState = await bob.PostAsync("/connect/logout", Form(new() { ["logout_state"] = alicePage["logout_state"] }));
        LogoutFlow.IsConfirmationPage(await bobWithAliceState.Content.ReadAsStringAsync()).Should().BeTrue();
        (await SessionStatusAsync(bobSession.id)).Should().Be("active", "a state issued for another session confirms nothing");

        // Not a state at all.
        var forged = await alice.PostAsync("/connect/logout", Form(new() { ["logout_state"] = "not-a-state" }));
        LogoutFlow.IsConfirmationPage(await forged.Content.ReadAsStringAsync()).Should().BeTrue();
        (await SessionStatusAsync(aliceSession.id)).Should().Be("active", "a value this server did not issue confirms nothing");

        await LogoutFlow.SignOutAsync(alice);
        await LogoutFlow.SignOutAsync(bob);
    }

    [Fact]
    public async Task The_relying_partys_parameters_survive_the_confirmation()
    {
        var (browser, _) = await LoginAsync();
        var session = await NewestActiveSessionAsync();

        var page = await browser.GetAsync(
            "/connect/logout?post_logout_redirect_uri=" + Uri.EscapeDataString(ProductionHttpFixture.TestRedirectUri) + "&state=rp-state-1");
        var fields = LogoutFlow.HiddenFields(await page.Content.ReadAsStringAsync());
        fields.Should().ContainKey("post_logout_redirect_uri").WhoseValue.Should().Be(ProductionHttpFixture.TestRedirectUri);
        fields.Should().ContainKey("state").WhoseValue.Should().Be("rp-state-1");

        var done = await LogoutFlow.ConfirmAsync(browser, page);
        done.StatusCode.Should().Be(HttpStatusCode.Redirect, "a registered post_logout_redirect_uri is honoured once the End-User confirmed");
        done.Headers.Location!.ToString().Should().StartWith(ProductionHttpFixture.TestRedirectUri);
        // RP-Initiated Logout 1.0 §3: the OP passes the RP's state back on the post-logout redirect.
        done.Headers.Location!.Query.Should().Contain("state=rp-state-1");
        (await SessionStatusAsync(session.id)).Should().Be("revoked");
    }

    // ── helpers ──

    private async Task<(HttpClient Browser, CookieContainer Jar)> LoginAsync()
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
        HasSessionCookie(jar).Should().BeTrue("login must issue the session cookie");
        return (client, jar);
    }

    private bool HasSessionCookie(CookieContainer jar)
    {
        foreach (Cookie c in jar.GetCookies(new Uri(_fx.BaseUrl)))
        {
            if (c.Name.EndsWith("redb.identity.session", StringComparison.Ordinal) && !string.IsNullOrEmpty(c.Value))
                return true;
        }
        return false;
    }

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

    private static FormUrlEncodedContent Form(Dictionary<string, string> kv) => new(kv);
}
