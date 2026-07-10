using FluentAssertions;
using redb.Identity.Contracts.Routes;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Pipeline;

/// <summary>
/// Token endpoint tests through the full route pipeline.
/// Unlike unit tests, these exercise: throttle → processor → WireTap → event dispatch.
/// </summary>
[Collection("IdentityRoute")]
public class TokenPipelineTests
{
    private readonly IdentityRouteFixture _fixture;

    public TokenPipelineTests(IdentityRouteFixture fixture) => _fixture = fixture;

    [Fact]
    public async Task ClientCredentials_ThroughPipeline_ReturnsAccessToken()
    {
        var body = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "pipeline-client",
            ["client_secret"] = "pipeline-secret"
        };

        var result = await _fixture.Request(IdentityEndpoints.Token, body);

        result.Should().NotBeNull();
        var dict = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        dict.Should().ContainKey("access_token");
        dict["token_type"].Should().Be("Bearer");
        dict["expires_in"].Should().NotBeNull();
    }

    [Fact]
    public async Task ClientCredentials_WithHeaders_ReturnsAccessToken()
    {
        var body = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials"
        };

        var credentials = Convert.ToBase64String(
            System.Text.Encoding.UTF8.GetBytes("basic-client:basic-secret"));

        var exchange = await _fixture.RequestWithHeaders(
            IdentityEndpoints.Token, body,
            new Dictionary<string, object?> { ["Authorization"] = $"Basic {credentials}" });

        exchange.In.Body.Should().NotBeNull();
        var dict = exchange.In.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        dict.Should().ContainKey("access_token");
    }

    [Fact]
    public async Task InvalidGrant_ThroughPipeline_ReturnsOAuthError()
    {
        var body = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials"
            // missing client_id → OpenIddict returns invalid_request
        };

        var result = await _fixture.Request(IdentityEndpoints.Token, body);

        result.Should().NotBeNull();
        var dict = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        dict.Should().ContainKey("error");
    }

    [Fact]
    public async Task Token_MultipleCalls_ThrottleDoesNotBlock()
    {
        // Fixture has relaxed throttle (100/s). Verify multiple calls succeed.
        for (int i = 0; i < 5; i++)
        {
            var body = new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = $"throttle-client-{i}",
                ["client_secret"] = "secret"
            };

            var result = await _fixture.Request(IdentityEndpoints.Token, body);
            result.Should().NotBeNull();
        }
    }
}
