using System.Net;
using System.Text.Json;
using AwesomeAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Http.E2E;

/// <summary>
/// A client that sends <c>Authorization: Basic</c> attempts client authentication through the header. When the value
/// cannot be read (not base64, or no <c>client_id:client_secret</c> pair) the attempt failed: the token, introspection
/// and revocation endpoints answer 401 <c>invalid_client</c> (RFC 6749 section 5.2). Up to this change the token
/// endpoint answered such a request with a 500.
/// </summary>
[Collection("ProductionHttp")]
public sealed class UnreadableBasicCredentialsTests
{
    private const string NotBase64 = "!!!not-base64!!!";

    private readonly ProductionHttpFixture _fx;

    public UnreadableBasicCredentialsTests(ProductionHttpFixture fx) => _fx = fx;

    public static TheoryData<string, string> Cases()
    {
        var data = new TheoryData<string, string>();
        foreach (var endpoint in new[] { "/connect/token", "/connect/introspect", "/connect/revocation" })
        {
            data.Add(endpoint, NotBase64);
            data.Add(endpoint, Convert.ToBase64String("no-colon-here"u8));
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task UnreadableBasicValue_AnswersInvalidClient(string endpoint, string basic)
    {
        var (status, error, body) = await Post(endpoint, basic);

        status.Should().Be(HttpStatusCode.Unauthorized, body);
        error.Should().Be("invalid_client", body);
    }

    [Fact]
    public async Task ReadableBasicCredentials_StillAuthenticate()
    {
        var basic = Convert.ToBase64String(
            System.Text.Encoding.UTF8.GetBytes(ProductionHttpFixture.TestClientId + ":" + ProductionHttpFixture.TestClientSecret));

        var (status, error, body) = await Post("/connect/token", basic);

        status.Should().Be(HttpStatusCode.OK, body);
        error.Should().BeNull(body);
    }

    private async Task<(HttpStatusCode Status, string? Error, string Body)> Post(string endpoint, string basic)
    {
        var form = endpoint == "/connect/token"
            ? new Dictionary<string, string> { ["grant_type"] = "client_credentials" }
            : new Dictionary<string, string> { ["token"] = "opaque" };

        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint) { Content = new FormUrlEncodedContent(form) };
        request.Headers.TryAddWithoutValidation("Authorization", $"Basic {basic}");

        using var response = await _fx.Http.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();
        string? error = null;
        if (body.TrimStart().StartsWith('{')
            && JsonDocument.Parse(body).RootElement.TryGetProperty("error", out var e))
            error = e.GetString();
        return (response.StatusCode, error, body);
    }
}
