using System.Net;
using System.Net.Http;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace redb.Identity.Web.Tests;

public sealed class MfaAndSignedOutPagesTests : IClassFixture<WebHostFixture>
{
    private readonly WebHostFixture _factory;

    public MfaAndSignedOutPagesTests(WebHostFixture factory) { _factory = factory; }

    [Fact]
    public async Task Get_mfa_challenge_without_cookie_renders_expired_message()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var resp = await client.GetAsync("/mfa-challenge");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);

        var html = await resp.Content.ReadAsStringAsync();
        // Without the identity.web.mfa cookie the page must show the expired-session UX
        // and link back to /login rather than rendering the code form.
        html.Should().Contain("expired");
        html.Should().Contain("/login");
        html.Should().NotContain("name=\"code\"");
    }

    [Fact]
    public async Task Get_mfa_cancel_clears_cookie_and_redirects_to_login()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var resp = await client.GetAsync("/api/auth/mfa/cancel");
        resp.StatusCode.Should().BeOneOf(HttpStatusCode.Found, HttpStatusCode.Redirect);
        resp.Headers.Location!.OriginalString.Should().Contain("/login");
        resp.Headers.Location.OriginalString.Should().Contain("mfa_cancelled");
    }

    [Fact]
    public async Task Get_signed_out_renders_confirmation_page()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var resp = await client.GetAsync("/signed-out");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);

        var html = await resp.Content.ReadAsStringAsync();
        html.Should().Contain("signed out");
        html.Should().Contain("/login");
    }
}
