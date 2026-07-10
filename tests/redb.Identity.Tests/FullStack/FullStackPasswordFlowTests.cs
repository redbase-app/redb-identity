using System.Net;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// Full-stack E2E tests for the Resource Owner Password Credentials (ROPC) flow via HTTP.
/// Path: HTTP → Kestrel → HTTP facade → direct-vm:// → OpenIddict → redb stores → PostgreSQL.
/// </summary>
[Collection("ProductionHttp")]
public class FullStackPasswordFlowTests
{
    private readonly ProductionHttpFixture _fx;
    private readonly HttpClient _http;

    public FullStackPasswordFlowTests(ProductionHttpFixture fx)
    {
        _fx = fx;
        _http = fx.Http;
    }

    // ══════════════════════════════════════════════
    //  Happy path — password grant → tokens
    // ══════════════════════════════════════════════

    [Fact]
    public async Task PasswordGrant_ValidCredentials_ReturnsTokens()
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = ProductionHttpFixture.TestUsername,
            ["password"] = ProductionHttpFixture.TestPassword,
            ["client_id"] = ProductionHttpFixture.TestClientId,
            ["client_secret"] = ProductionHttpFixture.TestClientSecret,
            ["scope"] = "openid profile email"
        });

        var resp = await _http.PostAsync("/connect/token", content);

        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            "password grant failed: {0}", await resp.Content.ReadAsStringAsync());
        var json = await ParseJson(resp);

        json.TryGetProperty("access_token", out var at).Should().BeTrue();
        at.GetString()!.Split('.').Should().HaveCount(3, "access_token should be a JWT");
        json.GetProperty("token_type").GetString().Should().Be("Bearer");
    }

    [Fact]
    public async Task PasswordGrant_WithOfflineAccess_ReturnsRefreshToken()
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = ProductionHttpFixture.TestUsername,
            ["password"] = ProductionHttpFixture.TestPassword,
            ["client_id"] = ProductionHttpFixture.TestClientId,
            ["client_secret"] = ProductionHttpFixture.TestClientSecret,
            ["scope"] = "openid offline_access"
        });

        var resp = await _http.PostAsync("/connect/token", content);

        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            "password grant failed: {0}", await resp.Content.ReadAsStringAsync());
        var json = await ParseJson(resp);

        json.TryGetProperty("access_token", out _).Should().BeTrue();
        json.TryGetProperty("refresh_token", out _).Should().BeTrue(
            "offline_access scope should yield a refresh_token");
    }

    // ══════════════════════════════════════════════
    //  Error paths
    // ══════════════════════════════════════════════

    [Fact]
    public async Task PasswordGrant_WrongPassword_ReturnsError()
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = ProductionHttpFixture.TestUsername,
            ["password"] = "completely-wrong-password",
            ["client_id"] = ProductionHttpFixture.TestClientId,
            ["client_secret"] = ProductionHttpFixture.TestClientSecret,
            ["scope"] = "openid"
        });

        var resp = await _http.PostAsync("/connect/token", content);

        resp.IsSuccessStatusCode.Should().BeFalse();
        var json = await ParseJson(resp);
        json.GetProperty("error").GetString().Should().Be("access_denied");
    }

    [Fact]
    public async Task PasswordGrant_NonExistentUser_ReturnsError()
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = "nonexistent-user-12345",
            ["password"] = "SomePassword123!",
            ["client_id"] = ProductionHttpFixture.TestClientId,
            ["client_secret"] = ProductionHttpFixture.TestClientSecret,
            ["scope"] = "openid"
        });

        var resp = await _http.PostAsync("/connect/token", content);

        resp.IsSuccessStatusCode.Should().BeFalse();
        var json = await ParseJson(resp);
        json.GetProperty("error").GetString().Should().Be("access_denied");
    }

    [Fact]
    public async Task PasswordGrant_MissingUsername_ReturnsError()
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["password"] = "SomePassword123!",
            ["client_id"] = ProductionHttpFixture.TestClientId,
            ["client_secret"] = ProductionHttpFixture.TestClientSecret,
            ["scope"] = "openid"
        });

        var resp = await _http.PostAsync("/connect/token", content);

        resp.IsSuccessStatusCode.Should().BeFalse();
        var json = await ParseJson(resp);
        json.TryGetProperty("error", out _).Should().BeTrue();
    }

    [Fact]
    public async Task PasswordGrant_ClientWithoutPermission_ReturnsError()
    {
        // Management client has no password grant permission
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = ProductionHttpFixture.TestUsername,
            ["password"] = ProductionHttpFixture.TestPassword,
            ["client_id"] = ProductionHttpFixture.TestMgmtClientId,
            ["client_secret"] = ProductionHttpFixture.TestMgmtSecret,
            ["scope"] = "openid"
        });

        var resp = await _http.PostAsync("/connect/token", content);

        resp.IsSuccessStatusCode.Should().BeFalse();
        var json = await ParseJson(resp);
        json.TryGetProperty("error", out _).Should().BeTrue();
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
