using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using AwesomeAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Webhooks;

/// <summary>Updating a webhook subscription over the HTTP management API changes it.</summary>
[Collection("ProductionHttp")]
public class WebhookUpdateTests
{
    private readonly ProductionHttpFixture _fx;
    public WebhookUpdateTests(ProductionHttpFixture fx) => _fx = fx;

    [Fact]
    public async Task APut_ChangesTheFieldsItCarries_AndLeavesTheOthers()
    {
        using var created = await SendAsync(HttpMethod.Post, "/api/v1/identity/webhooks",
            new { url = "http://127.0.0.1:9/hook", displayName = "update-test", timeoutMs = 2000 });
        var createdBody = await created.Content.ReadAsStringAsync();
        ((int)created.StatusCode).Should().BeInRange(200, 299, createdBody);
        var sub = JsonDocument.Parse(createdBody).RootElement.GetProperty("id").ToString();
        try
        {
            using var put = await SendAsync(HttpMethod.Put, $"/api/v1/identity/webhooks/{sub}",
                new { enabled = false, displayName = "renamed", timeoutMs = 1500 });
            ((int)put.StatusCode).Should().Be(200, await put.Content.ReadAsStringAsync());

            using var get = await SendAsync(HttpMethod.Get, $"/api/v1/identity/webhooks/{sub}", null);
            var body = JsonDocument.Parse(await get.Content.ReadAsStringAsync()).RootElement;
            body.GetProperty("enabled").GetBoolean().Should().BeFalse();
            body.GetProperty("displayName").GetString().Should().Be("renamed");
            body.GetProperty("timeoutMs").GetInt32().Should().Be(1500);
            body.GetProperty("url").GetString().Should().Be("http://127.0.0.1:9/hook");
        }
        finally
        {
            using var _ = await SendAsync(HttpMethod.Delete, $"/api/v1/identity/webhooks/{sub}", null);
        }
    }

    private Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, object? body)
    {
        var request = new HttpRequestMessage(method, path);
        if (body is not null) request.Content = JsonContent.Create(body);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fx.ManagementToken);
        return _fx.Http.SendAsync(request);
    }
}
