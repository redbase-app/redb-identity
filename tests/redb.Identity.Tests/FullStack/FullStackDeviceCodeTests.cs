using System.Net;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// Full-stack E2E tests for RFC 8628 Device Code flow via HTTP.
/// Path: HTTP → Kestrel → HTTP facade → direct-vm:// → OpenIddict → redb stores → PostgreSQL.
/// </summary>
[Collection("ProductionHttp")]
public class FullStackDeviceCodeTests
{
    private readonly ProductionHttpFixture _fx;
    private readonly HttpClient _http;

    public FullStackDeviceCodeTests(ProductionHttpFixture fx)
    {
        _fx = fx;
        _http = fx.Http;
    }

    // ══════════════════════════════════════════════
    //  Device Authorization — happy path
    // ══════════════════════════════════════════════

    [Fact]
    public async Task DeviceAuthorization_ReturnsDeviceAndUserCodes()
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = ProductionHttpFixture.TestPublicClientId,
            ["scope"] = "openid profile"
        });

        var resp = await _http.PostAsync("/connect/deviceauthorization", content);

        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            "device authorization failed: {0}", await resp.Content.ReadAsStringAsync());
        var json = await ParseJson(resp);

        json.TryGetProperty("device_code", out var dc).Should().BeTrue("response must contain device_code");
        dc.GetString().Should().NotBeNullOrEmpty();

        json.TryGetProperty("user_code", out var uc).Should().BeTrue("response must contain user_code");
        uc.GetString().Should().NotBeNullOrEmpty();

        json.TryGetProperty("verification_uri", out _).Should().BeTrue("response must contain verification_uri");
        json.TryGetProperty("expires_in", out var exp).Should().BeTrue("response must contain expires_in");
        exp.GetInt32().Should().BeGreaterThan(0);
    }

    // ══════════════════════════════════════════════
    //  Token polling — authorization_pending
    // ══════════════════════════════════════════════

    [Fact]
    public async Task DeviceCode_Poll_BeforeApproval_ReturnsAuthorizationPending()
    {
        // Step 1: Obtain device code
        var authContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = ProductionHttpFixture.TestPublicClientId,
            ["scope"] = "openid"
        });
        var authResp = await _http.PostAsync("/connect/deviceauthorization", authContent);
        authResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var authJson = await ParseJson(authResp);
        var deviceCode = authJson.GetProperty("device_code").GetString()!;

        // Step 2: Poll token endpoint — should get authorization_pending
        var tokenContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code",
            ["device_code"] = deviceCode,
            ["client_id"] = ProductionHttpFixture.TestPublicClientId
        });
        var tokenResp = await _http.PostAsync("/connect/token", tokenContent);

        tokenResp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var tokenJson = await ParseJson(tokenResp);
        tokenJson.GetProperty("error").GetString().Should().Be("authorization_pending");
    }

    // ══════════════════════════════════════════════
    //  Error paths
    // ══════════════════════════════════════════════

    [Fact]
    public async Task DeviceAuthorization_UnknownClient_ReturnsError()
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = "nonexistent-client-id",
            ["scope"] = "openid"
        });

        var resp = await _http.PostAsync("/connect/deviceauthorization", content);

        resp.IsSuccessStatusCode.Should().BeFalse("unknown client should be rejected");
        var json = await ParseJson(resp);
        json.TryGetProperty("error", out _).Should().BeTrue();
    }

    [Fact]
    public async Task DeviceAuthorization_MissingClientId_ReturnsError()
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["scope"] = "openid"
        });

        var resp = await _http.PostAsync("/connect/deviceauthorization", content);

        resp.IsSuccessStatusCode.Should().BeFalse("missing client_id should be rejected");
        var json = await ParseJson(resp);
        json.TryGetProperty("error", out _).Should().BeTrue();
    }

    [Fact]
    public async Task DeviceAuthorization_ClientWithoutPermission_ReturnsError()
    {
        // Management client has no device code permissions
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = ProductionHttpFixture.TestMgmtClientId,
            ["client_secret"] = ProductionHttpFixture.TestMgmtSecret,
            ["scope"] = "openid"
        });

        var resp = await _http.PostAsync("/connect/deviceauthorization", content);

        resp.IsSuccessStatusCode.Should().BeFalse("client without device_code permission should be rejected");
    }

    [Fact]
    public async Task DeviceCode_Poll_InvalidDeviceCode_ReturnsError()
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code",
            ["device_code"] = "invalid-device-code-12345",
            ["client_id"] = ProductionHttpFixture.TestPublicClientId
        });

        var resp = await _http.PostAsync("/connect/token", content);

        resp.IsSuccessStatusCode.Should().BeFalse();
        var json = await ParseJson(resp);
        json.TryGetProperty("error", out _).Should().BeTrue();
    }

    // ══════════════════════════════════════════════
    //  Discovery — device code in discovery
    // ══════════════════════════════════════════════

    [Fact]
    public async Task Discovery_ContainsDeviceAuthorizationEndpoint()
    {
        var resp = await _http.GetAsync("/.well-known/openid-configuration");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var json = await ParseJson(resp);

        json.TryGetProperty("device_authorization_endpoint", out var ep).Should()
            .BeTrue("discovery must include device_authorization_endpoint when enabled");
        ep.GetString().Should().Contain("/connect/deviceauthorization");

        // grant_types_supported should include device_code
        var grants = json.GetProperty("grant_types_supported");
        grants.EnumerateArray().Select(g => g.GetString())
            .Should().Contain("urn:ietf:params:oauth:grant-type:device_code");
    }

    // ══════════════════════════════════════════════
    //  Helpers
    // ══════════════════════════════════════════════

    private static async Task<JsonElement> ParseJson(HttpResponseMessage resp)
    {
        var body = await resp.Content.ReadAsStringAsync();
        return JsonDocument.Parse(body).RootElement;
    }
}
