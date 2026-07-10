using System.Net;
using System.Net.Http;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace redb.Identity.Web.Tests;

/// <summary>
/// F-1.1 regression test: <c>/api/auth/login</c> must reject form POSTs that are
/// missing the antiforgery token, even with valid-looking credentials.
/// </summary>
public sealed class CsrfProtectionTests : IClassFixture<WebHostFixture>
{
    private readonly WebHostFixture _factory;

    public CsrfProtectionTests(WebHostFixture factory) { _factory = factory; }

    [Fact]
    public async Task Post_login_without_antiforgery_token_is_rejected()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var form = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("username", "anyone"),
            new KeyValuePair<string, string>("password", "anything"),
        });

        var resp = await client.PostAsync("/api/auth/login", form);

        // ASP.NET Core antiforgery returns 400 BadRequest when the token is absent
        // or invalid on a [FromForm] minimal API endpoint.
        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }
}
