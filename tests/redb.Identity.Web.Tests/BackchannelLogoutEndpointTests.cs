using System.Net;
using System.Net.Http;
using System.Text;
using FluentAssertions;
using Xunit;

namespace redb.Identity.Web.Tests;

public sealed class BackchannelLogoutEndpointTests : IClassFixture<WebHostFixture>
{
    private readonly WebHostFixture _factory;

    public BackchannelLogoutEndpointTests(WebHostFixture factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Post_bcl_sink_without_token_returns_400()
    {
        var client = _factory.CreateClient();
        var content = new StringContent("", Encoding.UTF8, "application/x-www-form-urlencoded");

        var resp = await client.PostAsync("/bcl/sink", content);

        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Post_bcl_sink_with_invalid_token_does_not_succeed()
    {
        var client = _factory.CreateClient();
        var content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("logout_token", "not-a-real-jwt"),
        });

        var resp = await client.PostAsync("/bcl/sink", content);

        // Invalid JWT must NOT succeed.
        // 400 = endpoint validated and rejected;
        // 500 = couldn't even fetch signing keys (test fixture has unreachable authority — also a valid rejection).
        resp.StatusCode.Should().BeOneOf(HttpStatusCode.BadRequest, HttpStatusCode.InternalServerError);
    }
}
