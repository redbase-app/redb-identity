using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using AwesomeAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// Dynamic client registration takes no part in the Idempotency-Key cache. A registrant has no caller identity of its
/// own to key a replay by: the initial access token is one value shared by every registrant. Before, a second
/// registrant that sent the same key got the first registrant's answer back, its client_secret included.
/// </summary>
[Collection("ProductionHttp")]
public class DynamicRegistrationNotCachedTests
{
    private readonly ProductionHttpFixture _fx;

    public DynamicRegistrationNotCachedTests(ProductionHttpFixture fx) => _fx = fx;

    [Fact]
    public async Task A_second_registration_with_the_same_key_registers_its_own_client()
    {
        var key = "dcr-" + Guid.NewGuid().ToString("N");

        var (first, firstReplayed) = await RegisterAsync(key, "first registrant");
        var (second, secondReplayed) = await RegisterAsync(key, "second registrant");

        firstReplayed.Should().BeFalse();
        secondReplayed.Should().BeFalse("registration answers are never replayed");
        second.GetProperty("client_id").GetString().Should().NotBe(first.GetProperty("client_id").GetString());
        second.GetProperty("client_secret").GetString().Should().NotBe(first.GetProperty("client_secret").GetString());
        second.GetProperty("client_name").GetString().Should().Be("second registrant");
    }

    private async Task<(JsonElement Body, bool Replayed)> RegisterAsync(string idempotencyKey, string clientName)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/connect/register")
        {
            Content = JsonContent.Create(new
            {
                redirect_uris = new[] { "http://localhost/callback" },
                client_name = clientName,
            }),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ProductionHttpFixture.DynamicRegAccessToken);
        request.Headers.TryAddWithoutValidation("Idempotency-Key", idempotencyKey);

        var response = await _fx.Http.SendAsync(request);
        var text = await response.Content.ReadAsStringAsync();
        response.StatusCode.Should().Be(HttpStatusCode.Created, text);
        var replayed = response.Headers.TryGetValues("Idempotency-Replayed", out var values)
                       && values.Contains("true");
        return (JsonDocument.Parse(text).RootElement, replayed);
    }
}
