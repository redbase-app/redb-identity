using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using AwesomeAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// The granular scopes of the admin MFA surface over real HTTP: <c>identity:mfa:write</c> admits every operation under
/// <c>/api/v1/identity/mfa</c> for any user, <c>identity:mfa:read</c> only the status, and a scope of another surface
/// none of them.
/// </summary>
[Collection("ProductionHttp")]
public class AdminMfaGranularScopesTests
{
    private const string Base = "/api/v1/identity/mfa";

    private readonly ProductionHttpFixture _fx;

    public AdminMfaGranularScopesTests(ProductionHttpFixture fx) => _fx = fx;

    [Fact]
    public async Task A_token_with_identity_mfa_write_sets_up_reads_and_disables_another_users_totp()
    {
        var token = await GranularTokenAsync("identity:mfa:write");
        var userId = await CreateUserAsync();

        var setup = await SendAs(token, HttpMethod.Post, $"{Base}/totp/setup", new { userId, username = "granular-mfa" }, HttpStatusCode.OK);
        setup.GetProperty("secret_base32").GetString().Should().NotBeNullOrEmpty();
        await SendAs(token, HttpMethod.Get, $"{Base}/status/{userId}", null, HttpStatusCode.OK);
        await SendAs(token, HttpMethod.Delete, $"{Base}/totp/{userId}", null, HttpStatusCode.OK);
    }

    [Fact]
    public async Task A_token_with_identity_mfa_read_reads_the_status_and_changes_nothing()
    {
        var token = await GranularTokenAsync("identity:mfa:read");
        var userId = await CreateUserAsync();

        (await SendAs(token, HttpMethod.Get, $"{Base}/status/{userId}", null, HttpStatusCode.OK))
            .GetProperty("enabled").GetBoolean().Should().BeFalse();

        await SendAs(token, HttpMethod.Post, $"{Base}/totp/setup", new { userId, username = "granular-mfa" }, HttpStatusCode.Forbidden);
        await SendAs(token, HttpMethod.Post, $"{Base}/recovery-codes/regenerate", new { userId }, HttpStatusCode.Forbidden);
        await SendAs(token, HttpMethod.Delete, $"{Base}/totp/{userId}", null, HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task A_token_with_identity_users_write_alone_cannot_touch_mfa()
    {
        var token = await GranularTokenAsync("identity:users:write");
        var userId = await CreateUserAsync();

        await SendAs(token, HttpMethod.Get, $"{Base}/status/{userId}", null, HttpStatusCode.Forbidden);
        await SendAs(token, HttpMethod.Post, $"{Base}/totp/setup", new { userId, username = "granular-mfa" }, HttpStatusCode.Forbidden);
        await SendAs(token, HttpMethod.Delete, $"{Base}/totp/{userId}", null, HttpStatusCode.Forbidden);
    }

    private async Task<long> CreateUserAsync()
    {
        var login = "mfa-" + Guid.NewGuid().ToString("N")[..10];
        var created = await SendAs(_fx.ManagementToken, HttpMethod.Post, "/api/v1/identity/users",
            new { login, password = "Str0ng!Passw0rd", displayName = login }, HttpStatusCode.OK);
        return created.GetProperty("id").GetInt64();
    }

    private async Task<JsonElement> SendAs(string token, HttpMethod method, string path, object? body, HttpStatusCode expected)
    {
        var request = new HttpRequestMessage(method, path) { Content = body is null ? null : JsonContent.Create(body) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var response = await _fx.Http.SendAsync(request);
        var text = await response.Content.ReadAsStringAsync();
        response.StatusCode.Should().Be(expected, $"{method} {path}: {text}");
        return string.IsNullOrEmpty(text) ? default : JsonDocument.Parse(text).RootElement;
    }

    /// <summary>A client_credentials token of a fresh client allowed exactly <paramref name="scope"/>.</summary>
    private async Task<string> GranularTokenAsync(string scope)
    {
        var clientId = "mfa-scope-" + Guid.NewGuid().ToString("N")[..10];
        const string clientSecret = "mfa-scope-client-secret-1234";
        await SendAs(_fx.ManagementToken, HttpMethod.Post, "/api/v1/identity/applications", new
        {
            clientId,
            clientSecret,
            displayName = clientId,
            permissions = new[] { "ept:token", "gt:client_credentials", "scp:" + scope },
        }, HttpStatusCode.OK);

        var response = await _fx.Http.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["scope"] = scope,
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret,
        }));
        var text = await response.Content.ReadAsStringAsync();
        response.StatusCode.Should().Be(HttpStatusCode.OK, text);
        return JsonDocument.Parse(text).RootElement.GetProperty("access_token").GetString()!;
    }
}
