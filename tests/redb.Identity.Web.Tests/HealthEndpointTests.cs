using System.Net;
using System.Net.Http;
using FluentAssertions;
using Xunit;

namespace redb.Identity.Web.Tests;

public sealed class HealthEndpointTests : IClassFixture<WebHostFixture>
{
    private readonly WebHostFixture _factory;

    public HealthEndpointTests(WebHostFixture factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Get_health_returns_200_with_status_ok()
    {
        var client = _factory.CreateClient();
        var resp = await client.GetAsync("/health");

        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await resp.Content.ReadAsStringAsync();
        body.Should().Contain("\"status\"");
        body.Should().Contain("ok");
    }

    [Fact]
    public async Task Get_health_is_anonymous_no_redirect_to_login()
    {
        var opts = new HttpClientHandler { AllowAutoRedirect = false };
        var client = _factory.CreateDefaultClient(new Uri("http://localhost"));
        var resp = await client.GetAsync("/health");

        resp.StatusCode.Should().Be(HttpStatusCode.OK);
    }
}
