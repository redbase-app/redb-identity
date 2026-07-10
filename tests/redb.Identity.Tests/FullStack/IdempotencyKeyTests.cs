using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// E2 — full-stack tests for the <c>Idempotency-Key</c> response cache.
/// </summary>
[Collection("ProductionHttp")]
public class IdempotencyKeyTests
{
    private readonly ProductionHttpFixture _fx;
    private readonly HttpClient _http;

    public IdempotencyKeyTests(ProductionHttpFixture fx)
    {
        _fx = fx;
        _http = fx.Http;
    }

    private HttpRequestMessage WithAuth(HttpRequestMessage request)
    {
        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", _fx.ManagementToken);
        return request;
    }

    private static HttpRequestMessage WithIdemKey(HttpRequestMessage request, string key)
    {
        request.Headers.Add("Idempotency-Key", key);
        return request;
    }

    private async Task<JsonElement> ParseJson(HttpResponseMessage resp)
    {
        var s = await resp.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<JsonElement>(s);
    }

    private HttpRequestMessage CreateAppRequest(string clientId)
        => WithAuth(new HttpRequestMessage(HttpMethod.Post, "/api/v1/identity/applications")
        {
            Content = JsonContent.Create(new
            {
                clientId,
                clientSecret = "idem-test-secret",
                displayName = "E2 Idem App"
            })
        });

    [Fact]
    public async Task SameKey_TwoCalls_ReplaysCachedResponse_AndDoesNotCreateSecondResource()
    {
        var clientId = $"e2e-idem-{Guid.NewGuid():N}";
        var idemKey = Guid.NewGuid().ToString("N");

        // First call — creates the resource.
        var resp1 = await _http.SendAsync(WithIdemKey(CreateAppRequest(clientId), idemKey));
        resp1.StatusCode.Should().Be(HttpStatusCode.OK,
            "first create failed: {0}", await resp1.Content.ReadAsStringAsync());
        resp1.Headers.TryGetValues("Idempotency-Replayed", out _).Should().BeFalse(
            "first call must not be marked as replayed");
        var body1 = await ParseJson(resp1);

        // Second call with the SAME idempotency key — must replay (200, identical body),
        // and MUST NOT create a second application with the same clientId (which would have
        // failed with a duplicate-clientId error if the cache were bypassed).
        var resp2 = await _http.SendAsync(WithIdemKey(CreateAppRequest(clientId), idemKey));
        resp2.StatusCode.Should().Be(HttpStatusCode.OK,
            "replay must succeed: {0}", await resp2.Content.ReadAsStringAsync());
        resp2.Headers.TryGetValues("Idempotency-Replayed", out var replayedHeader).Should().BeTrue(
            "second call must surface the Idempotency-Replayed header");
        replayedHeader!.Single().Should().Be("true");
        var body2 = await ParseJson(resp2);

        body2.GetRawText().Should().Be(body1.GetRawText(),
            "replayed body must be byte-identical to the original response");
    }

    [Fact]
    public async Task DifferentKey_CreatesIndependentResource()
    {
        var clientIdA = $"e2e-idem-{Guid.NewGuid():N}";
        var clientIdB = $"e2e-idem-{Guid.NewGuid():N}";

        var key1 = Guid.NewGuid().ToString("N");
        var key2 = Guid.NewGuid().ToString("N");

        var respA = await _http.SendAsync(WithIdemKey(CreateAppRequest(clientIdA), key1));
        respA.StatusCode.Should().Be(HttpStatusCode.OK);

        var respB = await _http.SendAsync(WithIdemKey(CreateAppRequest(clientIdB), key2));
        respB.StatusCode.Should().Be(HttpStatusCode.OK);
        respB.Headers.TryGetValues("Idempotency-Replayed", out _).Should().BeFalse(
            "different key must NOT be served from cache");

        var bodyA = await ParseJson(respA);
        var bodyB = await ParseJson(respB);
        bodyA.GetRawText().Should().NotBe(bodyB.GetRawText(),
            "two distinct resources must produce two distinct bodies");
    }

    [Fact]
    public async Task NoIdempotencyKey_DoesNotCacheAnyResponse()
    {
        var clientId = $"e2e-idem-{Guid.NewGuid():N}";

        var resp1 = await _http.SendAsync(CreateAppRequest(clientId));
        resp1.StatusCode.Should().Be(HttpStatusCode.OK);
        resp1.Headers.TryGetValues("Idempotency-Replayed", out _).Should().BeFalse();

        // Same body, no idempotency key — second call hits the actual processor and the
        // duplicate clientId surfaces as a normal management-API error (NOT a 200 replay).
        var resp2 = await _http.SendAsync(CreateAppRequest(clientId));
        resp2.Headers.TryGetValues("Idempotency-Replayed", out _).Should().BeFalse(
            "without Idempotency-Key the response is never replayed");
        // We don't assert the exact status code of the duplicate; the contract is only
        // that no replay header is present and the request is processed normally.
    }

    [Fact]
    public async Task ReplayedResponse_CarriesSameStatusCode()
    {
        var clientId = $"e2e-idem-{Guid.NewGuid():N}";
        var idemKey = Guid.NewGuid().ToString("N");

        var resp1 = await _http.SendAsync(WithIdemKey(CreateAppRequest(clientId), idemKey));
        var status1 = resp1.StatusCode;

        var resp2 = await _http.SendAsync(WithIdemKey(CreateAppRequest(clientId), idemKey));
        resp2.StatusCode.Should().Be(status1, "cache must restore the original status code");
    }
}
