using System.Net;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// Full-stack E2E tests for B0.1: <c>RestrictScopeByGroupMembershipHandler</c>.
/// Validates that selected OAuth scopes (configured via
/// <see cref="redb.Identity.Core.Configuration.RedbIdentityOptions.ScopeRequiredGroups"/>)
/// are only granted to users belonging to the required group, while
/// <c>client_credentials</c> grants remain unaffected.
/// <para>
/// Fixture configures: <c>{ "identity:admin" → "identity-admins" }</c>.
/// Seeds an admin user (<see cref="ProductionHttpFixture.TestAdminUsername"/>)
/// added to the group, and a regular user (<see cref="ProductionHttpFixture.TestUsername"/>)
/// not in any group.
/// </para>
/// </summary>
[Collection("ProductionHttp")]
public class FullStackScopeAuthorizationTests
{
    private readonly ProductionHttpFixture _fx;
    private readonly HttpClient _http;

    public FullStackScopeAuthorizationTests(ProductionHttpFixture fx)
    {
        _fx = fx;
        _http = fx.Http;
    }

    // ════════════════════════════════════════════════════════════════
    //  Password grant — gated scope, gated by group membership
    // ════════════════════════════════════════════════════════════════

    [Fact]
    public async Task PasswordGrant_GatedScope_NotInGroup_ReturnsAccessDenied()
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = ProductionHttpFixture.TestUsername,         // not in identity-admins
            ["password"] = ProductionHttpFixture.TestPassword,
            ["client_id"] = ProductionHttpFixture.TestClientId,
            ["client_secret"] = ProductionHttpFixture.TestClientSecret,
            ["scope"] = $"openid {ProductionHttpFixture.AdminGatedScope}"
        });

        var resp = await _http.PostAsync("/connect/token", content);
        var bodyText = await resp.Content.ReadAsStringAsync();

        resp.IsSuccessStatusCode.Should().BeFalse(
            "user not in group should be denied the gated scope. Status={0} Body={1}",
            resp.StatusCode, bodyText);
        var json = JsonSerializer.Deserialize<JsonElement>(bodyText);
        json.GetProperty("error").GetString().Should().Be("access_denied");
        json.TryGetProperty("error_description", out var desc).Should().BeTrue();
        desc.GetString().Should().Contain(ProductionHttpFixture.AdminGroupName);
    }

    [Fact]
    public async Task PasswordGrant_GatedScope_InGroup_ReturnsToken()
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = ProductionHttpFixture.TestAdminUsername,    // member of identity-admins
            ["password"] = ProductionHttpFixture.TestAdminPassword,
            ["client_id"] = ProductionHttpFixture.TestClientId,
            ["client_secret"] = ProductionHttpFixture.TestClientSecret,
            ["scope"] = $"openid {ProductionHttpFixture.AdminGatedScope}"
        });

        var resp = await _http.PostAsync("/connect/token", content);

        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            "admin user should obtain the gated scope: {0}",
            await resp.Content.ReadAsStringAsync());
        var json = await ParseJson(resp);
        json.TryGetProperty("access_token", out var at).Should().BeTrue();
        at.GetString()!.Split('.').Should().HaveCount(3, "access_token should be a JWT");
    }

    [Fact]
    public async Task PasswordGrant_NonGatedScope_NotInAnyGroup_StillSucceeds()
    {
        // Sanity: handler must not affect requests that don't include a gated scope.
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = ProductionHttpFixture.TestUsername,
            ["password"] = ProductionHttpFixture.TestPassword,
            ["client_id"] = ProductionHttpFixture.TestClientId,
            ["client_secret"] = ProductionHttpFixture.TestClientSecret,
            ["scope"] = "openid profile"
        });

        var resp = await _http.PostAsync("/connect/token", content);

        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            "non-gated scopes must remain unaffected: {0}",
            await resp.Content.ReadAsStringAsync());
    }

    // ════════════════════════════════════════════════════════════════
    //  client_credentials — NOT gated by group membership
    // ════════════════════════════════════════════════════════════════

    [Fact]
    public async Task ClientCredentials_GatedScope_Succeeds()
    {
        // The management client has no user identity (sub = client_id, non-numeric).
        // Handler must skip and let the existing scp:* permission be the only gate.
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = ProductionHttpFixture.TestMgmtClientId,
            ["client_secret"] = ProductionHttpFixture.TestMgmtSecret,
            ["scope"] = ProductionHttpFixture.AdminGatedScope
        });

        var resp = await _http.PostAsync("/connect/token", content);

        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            "client_credentials must not be gated by user-group membership: {0}",
            await resp.Content.ReadAsStringAsync());
        var json = await ParseJson(resp);
        json.TryGetProperty("access_token", out _).Should().BeTrue();
    }

    // ════════════════════════════════════════════════════════════════
    //  Refresh token — gated scope must propagate restriction
    // ════════════════════════════════════════════════════════════════

    [Fact]
    public async Task RefreshToken_AfterAdminGrant_GatedScope_Succeeds()
    {
        // Step 1: admin user obtains a refresh token alongside the gated scope.
        var initialContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = ProductionHttpFixture.TestAdminUsername,
            ["password"] = ProductionHttpFixture.TestAdminPassword,
            ["client_id"] = ProductionHttpFixture.TestClientId,
            ["client_secret"] = ProductionHttpFixture.TestClientSecret,
            ["scope"] = $"openid offline_access {ProductionHttpFixture.AdminGatedScope}"
        });
        var initialResp = await _http.PostAsync("/connect/token", initialContent);
        initialResp.StatusCode.Should().Be(HttpStatusCode.OK,
            "initial admin grant must succeed: {0}", await initialResp.Content.ReadAsStringAsync());
        var initialJson = await ParseJson(initialResp);
        var refreshToken = initialJson.GetProperty("refresh_token").GetString()!;

        // Step 2: refresh — handler must re-evaluate group membership and allow.
        var refreshContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
            ["client_id"] = ProductionHttpFixture.TestClientId,
            ["client_secret"] = ProductionHttpFixture.TestClientSecret
        });
        var refreshResp = await _http.PostAsync("/connect/token", refreshContent);

        refreshResp.StatusCode.Should().Be(HttpStatusCode.OK,
            "admin still in group should refresh successfully: {0}",
            await refreshResp.Content.ReadAsStringAsync());
    }

    private static async Task<JsonElement> ParseJson(HttpResponseMessage resp)
    {
        var stream = await resp.Content.ReadAsStreamAsync();
        return await JsonSerializer.DeserializeAsync<JsonElement>(stream);
    }
}
