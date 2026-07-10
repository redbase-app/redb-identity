using FluentAssertions;
using redb.Identity.Contracts.Routes;
using redb.Identity.Tests.Infrastructure;
using redb.Route.Core;
using Xunit;

namespace redb.Identity.Tests.Pipeline;

/// <summary>
/// Introspection and Revocation endpoints through the full route pipeline.
/// Exercises: DoTry/DoCatch (introspection), WireTap (revocation), error handling.
/// </summary>
[Collection("IdentityRoute")]
public class IntrospectionRevocationPipelineTests
{
    private readonly IdentityRouteFixture _fixture;

    public IntrospectionRevocationPipelineTests(IdentityRouteFixture fixture) => _fixture = fixture;

    // ── Helpers ──

    private async Task<string> ObtainAccessToken()
    {
        var body = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "introspect-client",
            ["client_secret"] = "introspect-secret"
        };
        var result = await _fixture.Request(IdentityEndpoints.Token, body);
        var dict = (Dictionary<string, object?>)result!;
        return dict["access_token"]!.ToString()!;
    }

    /// <summary>
    /// Extracts the response dictionary from the exchange.
    /// The processor writes to Out.Body; after pipeline merge it may end up in In.Body.
    /// </summary>
    private static Dictionary<string, object?> GetResponseBody(Exchange exchange)
    {
        // Out.Body is the canonical location the processor writes to
        if (exchange.Out?.Body is Dictionary<string, object?> outDict)
            return outDict;
        // After In/Out merge, result may be in In.Body
        if (exchange.In.Body is Dictionary<string, object?> inDict)
            return inDict;
        throw new InvalidOperationException(
            $"No Dict<string,object?> found. In.Body={exchange.In.Body?.GetType()}, Out.Body={exchange.Out?.Body?.GetType()}");
    }

    // ── Introspection pipeline tests ──

    [Fact]
    public async Task Introspect_ValidToken_ThroughPipeline_ReturnsActive()
    {
        var token = await ObtainAccessToken();

        var body = new Dictionary<string, string> { ["token"] = token };
        var headers = new Dictionary<string, object?>
        {
            ["Authorization"] = "Basic " +
                Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("introspect-client:introspect-secret"))
        };

        var exchange = await _fixture.RequestWithHeaders(IdentityEndpoints.Introspect, body, headers);

        var dict = GetResponseBody(exchange);
        dict.Should().ContainKey("active");
        dict["active"].Should().Be(true);
    }

    [Fact]
    public async Task Introspect_InvalidToken_ThroughPipeline_ReturnsError()
    {
        var body = new Dictionary<string, string>
        {
            ["token"] = "completely-invalid-jwt-garbage"
        };
        var headers = new Dictionary<string, object?>
        {
            ["Authorization"] = "Basic " +
                Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("test-client:test-secret"))
        };

        var exchange = await _fixture.RequestWithHeaders(IdentityEndpoints.Introspect, body, headers);

        // OpenIddict returns an error for completely invalid tokens (not parseable JWT)
        var dict = GetResponseBody(exchange);
        dict.Should().ContainKey("error");
    }

    [Fact]
    public async Task Introspect_MissingToken_ThroughPipeline_ReturnsInvalidRequest()
    {
        var body = new Dictionary<string, string>();
        var headers = new Dictionary<string, object?>
        {
            ["Authorization"] = "Basic " +
                Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("test-client:test-secret"))
        };

        var exchange = await _fixture.RequestWithHeaders(IdentityEndpoints.Introspect, body, headers);

        var dict = GetResponseBody(exchange);
        dict.Should().ContainKey("error");
        dict["error"].Should().Be("invalid_request");
    }

    // ── Revocation pipeline tests ──

    [Fact]
    public async Task Revoke_ValidToken_ThroughPipeline_ReturnsSuccess()
    {
        var token = await ObtainAccessToken();

        var body = new Dictionary<string, string> { ["token"] = token };
        var headers = new Dictionary<string, object?>
        {
            ["Authorization"] = "Basic " +
                Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("introspect-client:introspect-secret"))
        };

        var exchange = await _fixture.RequestWithHeaders(IdentityEndpoints.Revoke, body, headers);

        // RFC 7009: successful revocation returns 200 with no error
        var dict = GetResponseBody(exchange);
        dict.Should().NotContainKey("error",
            "revocation should not return an error for a valid token");
    }

    [Fact]
    public async Task Revoke_InvalidToken_ThroughPipeline_Succeeds()
    {
        // RFC 7009 §2.1: invalid/unknown token → still 200
        var body = new Dictionary<string, string>
        {
            ["token"] = "not-a-real-token"
        };
        var headers = new Dictionary<string, object?>
        {
            ["Authorization"] = "Basic " +
                Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("test-client:test-secret"))
        };

        var exchange = await _fixture.RequestWithHeaders(IdentityEndpoints.Revoke, body, headers);

        // Should not throw — pipeline handles it gracefully
        exchange.Exception.Should().BeNull("revocation of invalid token should not throw");
    }

    [Fact]
    public async Task Revoke_MissingToken_ThroughPipeline_ReturnsError()
    {
        var body = new Dictionary<string, string>();
        var headers = new Dictionary<string, object?>
        {
            ["Authorization"] = "Basic " +
                Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("test-client:test-secret"))
        };

        var exchange = await _fixture.RequestWithHeaders(IdentityEndpoints.Revoke, body, headers);

        var dict = GetResponseBody(exchange);
        dict.Should().ContainKey("error");
        dict["error"].Should().Be("invalid_request");
    }
}
