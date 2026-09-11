using System.Net;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace redb.Identity.Web.Tests;

/// <summary>
/// Phase 3 (pages-not-dialogs): the modal editors became dedicated admin pages.
/// Without an authenticated principal the testable contract for each new route is
/// twofold and both halves matter:
/// <list type="bullet">
///   <item>NOT 404 — the route exists (a typo in @page would silently 404 while the
///     old AnonymousAccessTests-style "not 200" assertion still passed);</item>
///   <item>NOT 200 — the page never renders anonymously ([Authorize] is in place).</item>
/// </list>
/// Mutations on these pages go through the SDK inside the Blazor circuit, so the
/// raw-POST antiforgery negative of the public pages does not apply here
/// (CsrfProtectionTests keeps covering the public form endpoints).
/// </summary>
public sealed class Phase3PagesTests : IClassFixture<WebHostFixture>
{
    private readonly WebHostFixture _factory;

    public Phase3PagesTests(WebHostFixture factory) { _factory = factory; }

    [Theory]
    // П1 — federation provider pages
    [InlineData("/admin/federation/new")]
    [InlineData("/admin/federation/some-id")]
    // П2 — claim definitions
    [InlineData("/admin/claim-definitions/new")]
    [InlineData("/admin/claim-definitions/123")]
    // П3 — claim mappers
    [InlineData("/admin/claim-mappers/new")]
    [InlineData("/admin/claim-mappers/some-id")]
    // П4 — user creation wizard
    [InlineData("/admin/users/new")]
    // П5 — scopes and claim scopes
    [InlineData("/admin/scopes/new")]
    [InlineData("/admin/scopes/some-id")]
    [InlineData("/admin/claim-scopes/new")]
    [InlineData("/admin/claim-scopes/some-id")]
    // П6 — API resources catalogue
    [InlineData("/admin/api-resources")]
    // review catch — the group wizard left its modal for a page host
    [InlineData("/admin/groups/new")]
    public async Task New_admin_route_exists_and_never_renders_anonymously(string route)
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var resp = await client.GetAsync(route);

        resp.StatusCode.Should().NotBe(HttpStatusCode.NotFound,
            "the route must be registered — a 404 means the @page template broke");
        resp.StatusCode.Should().NotBe(HttpStatusCode.OK,
            "an [Authorize] admin page must not render for an anonymous request");
    }
}
