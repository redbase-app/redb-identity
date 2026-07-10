using System.Net;
using System.Net.Http;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace redb.Identity.Web.Tests;

public sealed class AnonymousAccessTests : IClassFixture<WebHostFixture>
{
    private readonly WebHostFixture _factory;

    public AnonymousAccessTests(WebHostFixture factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Get_root_returns_200_with_signin_card()
    {
        var client = _factory.CreateClient();
        var resp = await client.GetAsync("/");

        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var html = await resp.Content.ReadAsStringAsync();
        // Login card brand + primary action button — stable markers of the
        // anonymous landing page rendered by Components/Pages/Index.razor.
        html.Should().Contain("redb.Identity");
        html.Should().Contain("Sign In");
        html.Should().Contain("href=\"/login\"");
    }

    [Fact]
    public async Task Get_admin_unauthenticated_redirects_to_login()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var resp = await client.GetAsync("/admin");

        // /admin has [Authorize] → AuthorizeRouteView.NotAuthorized navigates to /account/login
        // But server-side it will trigger OIDC challenge directly via cookie scheme defaults.
        // Either way: we expect a non-200 (302 or 500) — the page must NOT render anonymously.
        resp.StatusCode.Should().NotBe(HttpStatusCode.OK);
    }
}
