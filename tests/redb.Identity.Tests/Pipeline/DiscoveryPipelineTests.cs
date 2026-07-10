using FluentAssertions;
using redb.Identity.Contracts.Routes;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Pipeline;

/// <summary>
/// Discovery and JWKS endpoints through the full route pipeline.
/// </summary>
[Collection("IdentityRoute")]
public class DiscoveryPipelineTests
{
    private readonly IdentityRouteFixture _fixture;

    public DiscoveryPipelineTests(IdentityRouteFixture fixture) => _fixture = fixture;

    [Fact]
    public async Task Discovery_ThroughPipeline_ReturnsConfiguration()
    {
        var result = await _fixture.Request(IdentityEndpoints.Discovery, new { });

        result.Should().NotBeNull();
        var dict = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        dict.Should().ContainKey("issuer");
        dict["issuer"]!.ToString().Should().Contain("identity.test.local");
    }

    [Fact]
    public async Task Jwks_ThroughPipeline_ReturnsKeys()
    {
        var result = await _fixture.Request(IdentityEndpoints.Jwks, new { });

        result.Should().NotBeNull();
        var dict = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        dict.Should().ContainKey("keys");
    }

    [Fact]
    public async Task Discovery_ContainsTokenEndpoint()
    {
        var result = await _fixture.Request(IdentityEndpoints.Discovery, new { });

        var dict = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        dict.Should().ContainKey("token_endpoint");
    }

    [Fact]
    public async Task Discovery_ContainsGrantTypesSupported()
    {
        var result = await _fixture.Request(IdentityEndpoints.Discovery, new { });

        var dict = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        dict.Should().ContainKey("grant_types_supported");
    }
}
