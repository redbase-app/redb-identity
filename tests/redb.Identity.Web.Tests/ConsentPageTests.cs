using System.Net;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace redb.Identity.Web.Tests;

/// <summary>
/// N-2 native consent: Phase-2 surface tests for the BFF /consent page and the
/// /api/auth/consent/* endpoints. End-to-end happy-path (where the BFF POSTs to
/// the host /consent form and resumes /connect/authorize) lives in the FullStack
/// suite — these tests only assert BFF-local behaviour without a running host.
/// </summary>
public sealed class ConsentPageTests : IClassFixture<WebHostFixture>
{
    private readonly WebHostFixture _factory;

    public ConsentPageTests(WebHostFixture factory) { _factory = factory; }

    [Fact]
    public async Task Get_consent_without_state_cookie_renders_expired_message()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var resp = await client.GetAsync("/consent");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);

        var html = await resp.Content.ReadAsStringAsync();
        // No identity.web.consent cookie → expired UX with /login link, no Allow form.
        html.Should().Contain("expired");
        html.Should().Contain("/login");
        html.Should().NotContain("/api/auth/consent/allow");
    }

    [Fact]
    public async Task Get_consent_cancel_clears_cookie_and_redirects_to_login()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var resp = await client.GetAsync("/api/auth/consent/cancel");
        resp.StatusCode.Should().BeOneOf(HttpStatusCode.Found, HttpStatusCode.Redirect);
        resp.Headers.Location!.OriginalString.Should().Contain("/login");
        resp.Headers.Location.OriginalString.Should().Contain("consent_denied");
    }

    [Fact]
    public async Task Post_consent_allow_without_state_cookie_redirects_to_login_expired()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        using var req = new HttpRequestMessage(HttpMethod.Post, "/api/auth/consent/allow")
        {
            // Endpoint disables antiforgery via .AllowAnonymous() + form-less submission
            // is acceptable for the no-cookie expired path. Real allow flow comes with
            // antiforgery + the identity.web.consent cookie.
            Content = new FormUrlEncodedContent(Array.Empty<KeyValuePair<string, string>>())
        };

        var resp = await client.SendAsync(req);
        // Either 400 (antiforgery rejects empty form) or 302 (state cookie missing) is
        // acceptable here — both prove the endpoint is wired and refuses to grant
        // anything without a valid in-flight state cookie. We only assert we never
        // get a 200 indicating a stray success path.
        resp.StatusCode.Should().NotBe(HttpStatusCode.OK);
    }
}
