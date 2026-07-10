using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// Full-stack E2E tests for consent management via HTTP.
/// Complete path: HTTP → Kestrel → bearer auth → controller → direct-vm:// → processor → PG.
/// </summary>
[Collection("ProductionHttp")]
public class FullStackConsentTests
{
    private readonly ProductionHttpFixture _fx;
    private readonly HttpClient _http;

    public FullStackConsentTests(ProductionHttpFixture fx)
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

    [Fact]
    public async Task Consents_ListEmpty_ViaHttp()
    {
        // Use a random userId that has no consents
        var userId = Random.Shared.NextInt64(900_000, 999_999);
        var req = WithAuth(new HttpRequestMessage(HttpMethod.Get,
            $"/api/v1/identity/consents?userId={userId}"));

        var resp = await _http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.OK);

        var json = await ParseJson(resp);
        json.ValueKind.Should().Be(JsonValueKind.Array);
        json.GetArrayLength().Should().Be(0);
    }

    [Fact]
    public async Task Consents_GrantThenList_ViaHttp()
    {
        // All test-side DB access must go through UseRedbAsync — _fx.Redb is captive and
        // would race with the audit-sink / OpenIddict pipeline that run on their own scopes.
        var (coreUserId, appId) = await _fx.UseRedbAsync(async redb =>
        {
            var consentService = new ConsentService(redb);
            var coreUser = await redb.UserProvider.GetUserByLoginAsync(ProductionHttpFixture.TestUsername)
                ?? throw new Exception("Test user not found");

            var app = await redb.Query<ApplicationProps>()
                .WhereRedb(o => o.ValueString == ProductionHttpFixture.TestClientId)
                .FirstOrDefaultAsync();
            app.Should().NotBeNull();

            await consentService.GrantAsync(coreUser.Id, app!.id, ["openid", "profile"]);
            return (coreUser.Id, app.id);
        });

        try
        {
            var req = WithAuth(new HttpRequestMessage(HttpMethod.Get,
                $"/api/v1/identity/consents?userId={coreUserId}"));
            var resp = await _http.SendAsync(req);
            resp.StatusCode.Should().Be(HttpStatusCode.OK);

            var json = await ParseJson(resp);
            json.ValueKind.Should().Be(JsonValueKind.Array);
            json.GetArrayLength().Should().BeGreaterThan(0);

            // Find the consent we just created
            var found = false;
            foreach (var item in json.EnumerateArray())
            {
                if (item.GetProperty("applicationId").GetInt64() == appId)
                {
                    item.GetProperty("userId").GetInt64().Should().Be(coreUserId);
                    item.GetProperty("clientId").GetString().Should().Be(ProductionHttpFixture.TestClientId);
                    item.GetProperty("status").GetString().Should().Be("valid");
                    found = true;
                    break;
                }
            }
            found.Should().BeTrue("should find the granted consent in the list");
        }
        finally
        {
            // Cleanup in its own scope
            await _fx.UseRedbAsync(async redb =>
            {
                var consentService = new ConsentService(redb);
                await consentService.RevokeAsync(coreUserId, appId);
            });
        }
    }

    [Fact]
    public async Task Consents_RevokeViaHttp()
    {
        var (coreUserId, appId) = await _fx.UseRedbAsync(async redb =>
        {
            var consentService = new ConsentService(redb);
            var coreUser = await redb.UserProvider.GetUserByLoginAsync(ProductionHttpFixture.TestUsername)
                ?? throw new Exception("Test user not found");
            var app = await redb.Query<ApplicationProps>()
                .WhereRedb(o => o.ValueString == ProductionHttpFixture.TestClientId)
                .FirstOrDefaultAsync();

            await consentService.GrantAsync(coreUser.Id, app!.id, ["openid"]);
            return (coreUser.Id, app.id);
        });

        // Revoke via HTTP
        var req = WithAuth(new HttpRequestMessage(HttpMethod.Delete,
            $"/api/v1/identity/consents?userId={coreUserId}&applicationId={appId}"));
        var resp = await _http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.OK);

        var json = await ParseJson(resp);
        json.GetProperty("success").GetBoolean().Should().BeTrue();
        json.GetProperty("revoked").GetInt32().Should().BeGreaterOrEqualTo(1);

        // Verify revoked in its own scope
        await _fx.UseRedbAsync(async redb =>
        {
            var consentService = new ConsentService(redb);
            var check = await consentService.CheckAsync(coreUserId, appId, ["openid"]);
            check.Should().BeNull();
        });
    }

    [Fact]
    public async Task Consents_RevokeAllViaHttp()
    {
        var coreUserId = await _fx.UseRedbAsync(async redb =>
        {
            var consentService = new ConsentService(redb);
            var coreUser = await redb.UserProvider.GetUserByLoginAsync(ProductionHttpFixture.TestUsername)
                ?? throw new Exception("Test user not found");
            var app1 = await redb.Query<ApplicationProps>()
                .WhereRedb(o => o.ValueString == ProductionHttpFixture.TestClientId)
                .FirstOrDefaultAsync();
            var app2 = await redb.Query<ApplicationProps>()
                .WhereRedb(o => o.ValueString == ProductionHttpFixture.TestPublicClientId)
                .FirstOrDefaultAsync();

            await consentService.GrantAsync(coreUser.Id, app1!.id, ["openid"]);
            await consentService.GrantAsync(coreUser.Id, app2!.id, ["openid", "profile"]);
            return coreUser.Id;
        });

        // Revoke all via HTTP
        var req = WithAuth(new HttpRequestMessage(HttpMethod.Delete,
            $"/api/v1/identity/consents/all?userId={coreUserId}"));
        var resp = await _http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.OK);

        var json = await ParseJson(resp);
        json.GetProperty("success").GetBoolean().Should().BeTrue();

        // Verify all revoked in its own scope
        await _fx.UseRedbAsync(async redb =>
        {
            var consentService = new ConsentService(redb);
            var list = await consentService.ListAsync(coreUserId);
            list.Should().BeEmpty();
        });
    }

    [Fact]
    public async Task Consents_NoBearerToken_Returns401()
    {
        var resp = await _http.GetAsync("/api/v1/identity/consents?userId=1");
        resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    private static async Task<JsonElement> ParseJson(HttpResponseMessage resp)
    {
        var body = await resp.Content.ReadAsStringAsync();
        return JsonDocument.Parse(body).RootElement;
    }
}
