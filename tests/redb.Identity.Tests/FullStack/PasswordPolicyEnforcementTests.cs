using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using redb.Core;
using redb.Identity.Contracts.Scim;
using redb.Identity.Core.Models;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// H10 Phase 4 — full-stack E2E tests for password policy enforcement (history reuse,
/// expiration on login, SCIM PATCH gap). Each test creates a fresh user via the admin
/// API to avoid coupling with the shared <c>e2e-user</c> fixture (which other tests
/// rely on for ROPC happy-path).
/// </summary>
[Collection("ProductionHttp")]
public class PasswordPolicyEnforcementTests
{
    private readonly ProductionHttpFixture _fx;
    private readonly HttpClient _http;

    public PasswordPolicyEnforcementTests(ProductionHttpFixture fx)
    {
        _fx = fx;
        _http = fx.Http;
    }

    // ════════════════════════════════════════════════════════════════
    // History reuse (Phase 2)
    // ════════════════════════════════════════════════════════════════

    [Fact]
    public async Task ChangePassword_ReusingPreviousPassword_Rejected()
    {
        var (login, id, originalPwd) = await CreateUserAsync();
        var pwd2 = $"Str0ng!Two{Guid.NewGuid():N}".Substring(0, 16);

        // Rotate: original → pwd2 → original (must fail because original is in history).
        await ChangePasswordAsync(id, originalPwd, pwd2)
            .Expect(HttpStatusCode.OK, "first rotation must succeed");

        var resp = await ChangePasswordAsync(id, pwd2, originalPwd);
        resp.IsSuccessStatusCode.Should().BeFalse(
            "rotating back to the original password must be blocked by the history check; body={0}",
            await resp.Content.ReadAsStringAsync());
        var body = await resp.Content.ReadAsStringAsync();
        body.Should().Contain("last", "policy error must mention the history-window");
    }

    [Fact]
    public async Task ChangePassword_BeyondHistoryWindow_Allowed()
    {
        // Default HistoryCount = 5 → after 6 distinct rotations, the original drops off
        // and may be reused again.
        var (login, id, originalPwd) = await CreateUserAsync();

        var passwords = new List<string> { originalPwd };
        for (int i = 0; i < 6; i++)
        {
            var next = $"Str0ng!{i}xX{Guid.NewGuid():N}".Substring(0, 16);
            await ChangePasswordAsync(id, passwords[^1], next)
                .Expect(HttpStatusCode.OK, $"rotation #{i + 1} must succeed");
            passwords.Add(next);
        }

        // Original password should now be reusable — verify a final rotation back to it.
        var resp = await ChangePasswordAsync(id, passwords[^1], originalPwd);
        resp.IsSuccessStatusCode.Should().BeTrue(
            "after rotating past the history window the original password must be reusable; body={0}",
            await resp.Content.ReadAsStringAsync());
    }

    // ════════════════════════════════════════════════════════════════
    // Expiration on login (Phase 3) — ROPC reject
    // ════════════════════════════════════════════════════════════════

    [Fact]
    public async Task PasswordGrant_WithExpiredPassword_RejectsWithInvalidGrant()
    {
        var (login, id, password) = await CreateUserAsync();

        // Backdate PasswordChangedAt so it falls outside MaxAge (default = 90 days).
        await ForcePasswordExpiredAsync(id);

        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = login,
            ["password"] = password,
            ["client_id"] = ProductionHttpFixture.TestClientId,
            ["client_secret"] = ProductionHttpFixture.TestClientSecret,
            ["scope"] = "openid"
        });

        var resp = await _http.PostAsync("/connect/token", content);

        resp.IsSuccessStatusCode.Should().BeFalse("expired password must not yield a token");
        var body = await resp.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(body).RootElement;
        json.GetProperty("error").GetString().Should().Be("invalid_grant",
            "ROPC password-expired must surface as invalid_grant; body={0}", body);
        json.TryGetProperty("error_description", out var desc).Should().BeTrue();
        desc.GetString().Should().Contain("expired", "error_description must mention expiration");
    }

    [Fact]
    public async Task ChangePassword_ResetsExpiration_NextLoginSucceeds()
    {
        var (login, id, originalPwd) = await CreateUserAsync();
        var newPwd = $"Str0ng!New{Guid.NewGuid():N}".Substring(0, 16);

        // Mark expired, then change the password — RecordPasswordHistoryAsync also
        // stamps PasswordChangedAt to now, so the next login should succeed.
        await ForcePasswordExpiredAsync(id);
        await ChangePasswordAsync(id, originalPwd, newPwd)
            .Expect(HttpStatusCode.OK, "rotation under expired password must still succeed via admin API");

        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = login,
            ["password"] = newPwd,
            ["client_id"] = ProductionHttpFixture.TestClientId,
            ["client_secret"] = ProductionHttpFixture.TestClientSecret,
            ["scope"] = "openid"
        });
        var resp = await _http.PostAsync("/connect/token", content);
        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            "after rotation, login with the new password must succeed; body={0}",
            await resp.Content.ReadAsStringAsync());
    }

    // ════════════════════════════════════════════════════════════════
    // SCIM PATCH password policy gap closure
    // ════════════════════════════════════════════════════════════════

    [Fact]
    public async Task ScimPatchPassword_WithWeakPassword_Returns400()
    {
        var (id, _) = await CreateScimUserAsync();

        var patch = new
        {
            schemas = new[] { "urn:ietf:params:scim:api:messages:2.0:PatchOp" },
            Operations = new object[]
            {
                new { op = "replace", path = "password", value = "short" }   // 5 chars, no digit/upper/special
            }
        };

        using var req = ScimRequest(HttpMethod.Patch, $"/scim/v2/Users/{id}");
        req.Content = new StringContent(JsonSerializer.Serialize(patch), Encoding.UTF8, "application/scim+json");

        var resp = await _http.SendAsync(req);
        var body = await resp.Content.ReadAsStringAsync();

        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest,
            "SCIM PATCH password must enforce the H10 policy (gap closure); body={0}", body);
    }

    [Fact]
    public async Task ScimPatchPassword_WithStrongPassword_Succeeds()
    {
        var (id, _) = await CreateScimUserAsync();

        var patch = new
        {
            schemas = new[] { "urn:ietf:params:scim:api:messages:2.0:PatchOp" },
            Operations = new object[]
            {
                new { op = "replace", path = "password", value = "Str0ng!Passw0rdScim" }
            }
        };

        using var req = ScimRequest(HttpMethod.Patch, $"/scim/v2/Users/{id}");
        req.Content = new StringContent(JsonSerializer.Serialize(patch), Encoding.UTF8, "application/scim+json");

        var resp = await _http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            "policy-compliant SCIM PATCH password must succeed; body={0}",
            await resp.Content.ReadAsStringAsync());
    }

    // ════════════════════════════════════════════════════════════════
    // Helpers
    // ════════════════════════════════════════════════════════════════

    /// <summary>
    /// Creates a fresh admin user via management API. Returns <c>(login, id, password)</c>.
    /// Password is policy-compliant (15 chars, mixed case, digit, special).
    /// </summary>
    private async Task<(string login, long id, string password)> CreateUserAsync()
    {
        var login = $"e2e-pwpol-{Guid.NewGuid():N}".Substring(0, 24);
        var password = $"Str0ng!P{Guid.NewGuid():N}".Substring(0, 16);

        var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/identity/users")
        {
            Content = JsonContent.Create(new { login, password })
        };
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fx.ManagementToken);
        var resp = await _http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            "user create must succeed; body={0}", await resp.Content.ReadAsStringAsync());

        var json = await resp.Content.ReadFromJsonAsync<JsonElement>();
        long id = ExtractId(json);
        id.Should().BeGreaterThan(0, "create response must include an id");
        return (login, id, password);
    }

    private static long ExtractId(JsonElement json)
    {
        // Response envelopes vary across processors — check common shapes.
        if (json.ValueKind == JsonValueKind.Object)
        {
            if (json.TryGetProperty("id", out var idEl) && idEl.ValueKind == JsonValueKind.Number)
                return idEl.GetInt64();
            if (json.TryGetProperty("Id", out var idEl2) && idEl2.ValueKind == JsonValueKind.Number)
                return idEl2.GetInt64();
            if (json.TryGetProperty("data", out var data))
                return ExtractId(data);
            if (json.TryGetProperty("user", out var user))
                return ExtractId(user);
        }
        return 0;
    }

    private async Task<HttpResponseMessage> ChangePasswordAsync(long userId, string oldPwd, string newPwd)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/identity/users/{userId}/change-password")
        {
            Content = JsonContent.Create(new
            {
                id = userId,
                oldPassword = oldPwd,
                newPassword = newPwd
            })
        };
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fx.ManagementToken);
        return await _http.SendAsync(req);
    }

    /// <summary>
    /// Backdates <see cref="UserProps.PasswordChangedAt"/> by 200 days so it falls
    /// outside the default 90-day MaxAge window. Writes the OIDC props row directly via
    /// PROPS — bypasses the policy hooks, which is exactly what we need to simulate an
    /// aged account.
    /// </summary>
    private async Task ForcePasswordExpiredAsync(long userId)
    {
        await _fx.UseRedbAsync(async (IRedbService redb) =>
        {
            var existing = await redb.Query<UserProps>()
                .WhereRedb(o => o.Key == userId)
                .FirstOrDefaultAsync();
            var aged = DateTimeOffset.UtcNow.AddDays(-200);
            if (existing is not null)
            {
                existing.Props.PasswordChangedAt = aged;
                await redb.SaveAsync(existing);
            }
            else
            {
                var fresh = new redb.Core.Models.Entities.RedbObject<UserProps>(
                    new UserProps { PasswordChangedAt = aged })
                {
                    key = userId
                };
                await redb.SaveAsync(fresh);
            }
        });
    }

    private async Task<(string id, string login)> CreateScimUserAsync()
    {
        var tag = Guid.NewGuid().ToString("N").Substring(0, 12);
        var user = new ScimUser
        {
            UserName = $"scim-pwpol-{tag}",
            DisplayName = $"SCIM PwPol {tag}"
        };

        using var req = ScimRequest(HttpMethod.Post, "/scim/v2/Users");
        req.Content = new StringContent(JsonSerializer.Serialize(user), Encoding.UTF8, ScimConstants.MediaType);
        var resp = await _http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.Created,
            "SCIM POST must succeed; body={0}", await resp.Content.ReadAsStringAsync());

        var json = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        return (json.GetProperty("id").GetString()!, user.UserName);
    }

    private HttpRequestMessage ScimRequest(HttpMethod method, string path)
    {
        var req = new HttpRequestMessage(method, path);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fx.ScimToken);
        req.Headers.Accept.ParseAdd("application/scim+json");
        return req;
    }
}

internal static class HttpResponseAssertExtensions
{
    public static async Task Expect(
        this Task<HttpResponseMessage> respTask,
        HttpStatusCode expected,
        string because)
    {
        var resp = await respTask;
        if (resp.StatusCode != expected)
        {
            var body = await resp.Content.ReadAsStringAsync();
            throw new Xunit.Sdk.XunitException(
                $"Expected {(int)expected} {expected} but got {(int)resp.StatusCode} {resp.StatusCode}: {because}\nBody: {body}");
        }
    }
}
