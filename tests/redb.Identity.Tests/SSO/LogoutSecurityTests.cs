using System.Net;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.SSO;

/// <summary>
/// Tests for <c>post_logout_redirect_uri</c> open redirect protection (Step 5a).
/// Verifies that only registered redirect URIs are honored during logout.
/// </summary>
[Collection("ProductionHttp")]
public class LogoutSecurityTests
{
    private readonly ProductionHttpFixture _fx;
    private readonly ITestOutputHelper _out;

    public LogoutSecurityTests(ProductionHttpFixture fx, ITestOutputHelper output)
    {
        _fx = fx;
        _out = output;
    }

    [Fact]
    public async Task Logout_UnregisteredRedirectUri_ShowsSignedOutPage()
    {
        // Login first to get a session
        var cookies = new CookieContainer();
        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            CookieContainer = cookies,
            UseCookies = true
        };
        using var client = new HttpClient(handler) { BaseAddress = new Uri(_fx.BaseUrl) };

        await LoginAsync(client);

        // Attempt logout with an unregistered URI (potential open redirect)
        var resp = await client.GetAsync(
            "/connect/logout?post_logout_redirect_uri=" +
            Uri.EscapeDataString("https://evil.example.com/steal-tokens"));

        // Should NOT redirect — should show "Signed Out" page instead
        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            because: "unregistered post_logout_redirect_uri must not cause a redirect");

        var body = await resp.Content.ReadAsStringAsync();
        body.Should().Contain("Signed Out",
            because: "should render the signed-out page instead of redirecting to evil URI");

        _out.WriteLine("Open redirect correctly blocked — showed signed-out page instead");
    }

    [Fact]
    public async Task Logout_RegisteredRedirectUri_Redirects()
    {
        // Login first
        var cookies = new CookieContainer();
        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            CookieContainer = cookies,
            UseCookies = true
        };
        using var client = new HttpClient(handler) { BaseAddress = new Uri(_fx.BaseUrl) };

        await LoginAsync(client);

        // Logout with the registered redirect URI
        var resp = await client.GetAsync(
            "/connect/logout?post_logout_redirect_uri=" +
            Uri.EscapeDataString(ProductionHttpFixture.TestRedirectUri));

        var body = await resp.Content.ReadAsStringAsync();
        _out.WriteLine($"Status: {resp.StatusCode}, Location: {resp.Headers.Location}");
        _out.WriteLine($"Body snippet: {body[..Math.Min(200, body.Length)]}");

        // Should redirect to the registered URI
        resp.StatusCode.Should().Be(HttpStatusCode.Redirect,
            because: "registered post_logout_redirect_uri should result in 302 redirect");

        resp.Headers.Location.Should().NotBeNull();
        resp.Headers.Location!.ToString().Should().StartWith(ProductionHttpFixture.TestRedirectUri);

        _out.WriteLine($"Registered URI correctly redirected to: {resp.Headers.Location}");
    }

    [Fact]
    public async Task Logout_NoRedirectUri_ShowsSignedOutPage()
    {
        var cookies = new CookieContainer();
        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            CookieContainer = cookies,
            UseCookies = true
        };
        using var client = new HttpClient(handler) { BaseAddress = new Uri(_fx.BaseUrl) };

        await LoginAsync(client);

        // Logout without post_logout_redirect_uri
        var resp = await client.GetAsync("/connect/logout");

        // Should show "Signed Out" page
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await resp.Content.ReadAsStringAsync();
        body.Should().Contain("Signed Out");

        _out.WriteLine("Logout without redirect URI shows signed-out page ✓");
    }

    [Fact]
    public async Task Logout_Post_UnregisteredRedirectUri_Blocked()
    {
        var cookies = new CookieContainer();
        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            CookieContainer = cookies,
            UseCookies = true
        };
        using var client = new HttpClient(handler) { BaseAddress = new Uri(_fx.BaseUrl) };

        await LoginAsync(client);

        // POST logout with unregistered URI
        var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["post_logout_redirect_uri"] = "https://evil.example.com/phish"
        });
        var resp = await client.PostAsync("/connect/logout", form);

        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            because: "unregistered URI via POST must not redirect");

        var body = await resp.Content.ReadAsStringAsync();
        body.Should().Contain("Signed Out");

        _out.WriteLine("POST logout with unregistered URI correctly blocked");
    }

    private static async Task LoginAsync(HttpClient client)
    {
        var loginForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = ProductionHttpFixture.TestUsername,
            ["password"] = ProductionHttpFixture.TestPassword
        });
        var resp = await client.PostAsync("/login", loginForm);
        // Login should succeed (200 or 302)
        ((int)resp.StatusCode).Should().BeOneOf(200, 302);
    }
}
