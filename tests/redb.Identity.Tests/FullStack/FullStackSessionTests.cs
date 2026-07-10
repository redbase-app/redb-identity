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
/// Full-stack E2E tests for session management via HTTP.
/// Complete path: HTTP → Kestrel → bearer auth → controller → direct-vm:// → processor → PG.
/// </summary>
[Collection("ProductionHttp")]
public class FullStackSessionTests
{
    private readonly ProductionHttpFixture _fx;
    private readonly HttpClient _http;

    public FullStackSessionTests(ProductionHttpFixture fx)
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
    public async Task Sessions_ListEmpty_ViaHttp()
    {
        var userId = Random.Shared.NextInt64(900_000, 999_999);
        var req = WithAuth(new HttpRequestMessage(HttpMethod.Get,
            $"/api/v1/identity/sessions?userId={userId}"));

        var resp = await _http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.OK);

        var json = await ParseJson(resp);
        json.ValueKind.Should().Be(JsonValueKind.Array);
        json.GetArrayLength().Should().Be(0);
    }

    [Fact]
    public async Task Sessions_CreateThenList_ViaHttp()
    {
        // Create a session directly
        var sessionService = new SessionService(_fx.Redb);
        var coreUser = await _fx.Redb.UserProvider.GetUserByLoginAsync(ProductionHttpFixture.TestUsername)
            ?? throw new Exception("Test user not found");

        var app = await _fx.Redb.Query<ApplicationProps>()
            .WhereRedb(o => o.ValueString == ProductionHttpFixture.TestClientId)
            .FirstOrDefaultAsync();
        app.Should().NotBeNull();

        var session = await sessionService.CreateAsync(coreUser.Id, app!.id);

        try
        {
            var req = WithAuth(new HttpRequestMessage(HttpMethod.Get,
                $"/api/v1/identity/sessions?userId={coreUser.Id}"));
            var resp = await _http.SendAsync(req);
            resp.StatusCode.Should().Be(HttpStatusCode.OK);

            var json = await ParseJson(resp);
            json.ValueKind.Should().Be(JsonValueKind.Array);
            json.GetArrayLength().Should().BeGreaterThan(0);

            // Find the session we just created
            var found = false;
            foreach (var item in json.EnumerateArray())
            {
                if (item.TryGetProperty("sessionId", out var sidProp)
                    && sidProp.GetInt64() == session.id)
                {
                    found = true;
                    item.GetProperty("status").GetString().Should().Be("active");
                    break;
                }
            }
            found.Should().BeTrue("Session should appear in the management API");
        }
        finally
        {
            await sessionService.RevokeAsync(session.id);
        }
    }

    [Fact]
    public async Task Sessions_Revoke_ViaHttp()
    {
        var sessionService = new SessionService(_fx.Redb);
        var coreUser = await _fx.Redb.UserProvider.GetUserByLoginAsync(ProductionHttpFixture.TestUsername)
            ?? throw new Exception("Test user not found");
        var app = await _fx.Redb.Query<ApplicationProps>()
            .WhereRedb(o => o.ValueString == ProductionHttpFixture.TestClientId)
            .FirstOrDefaultAsync();

        var session = await sessionService.CreateAsync(coreUser.Id, app!.id);

        // Revoke via HTTP
        var req = WithAuth(new HttpRequestMessage(HttpMethod.Delete,
            $"/api/v1/identity/sessions?sessionId={session.id}"));
        var resp = await _http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.OK);

        var json = await ParseJson(resp);
        json.GetProperty("success").GetBoolean().Should().BeTrue();
        json.GetProperty("revoked").GetInt32().Should().Be(1);
    }

    [Fact]
    public async Task Sessions_RevokeAll_ViaHttp()
    {
        var sessionService = new SessionService(_fx.Redb);
        var coreUser = await _fx.Redb.UserProvider.GetUserByLoginAsync(ProductionHttpFixture.TestUsername)
            ?? throw new Exception("Test user not found");
        var app = await _fx.Redb.Query<ApplicationProps>()
            .WhereRedb(o => o.ValueString == ProductionHttpFixture.TestClientId)
            .FirstOrDefaultAsync();

        await sessionService.CreateAsync(coreUser.Id, app!.id);
        await sessionService.CreateAsync(coreUser.Id, app!.id);

        // Revoke all via HTTP
        var req = WithAuth(new HttpRequestMessage(HttpMethod.Delete,
            $"/api/v1/identity/sessions/all?userId={coreUser.Id}"));
        var resp = await _http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.OK);

        var json = await ParseJson(resp);
        json.GetProperty("success").GetBoolean().Should().BeTrue();
        json.GetProperty("revoked").GetInt32().Should().BeGreaterOrEqualTo(2);

        // Verify list is empty
        var listReq = WithAuth(new HttpRequestMessage(HttpMethod.Get,
            $"/api/v1/identity/sessions?userId={coreUser.Id}"));
        var listResp = await _http.SendAsync(listReq);
        var listJson = await ParseJson(listResp);
        listJson.GetArrayLength().Should().Be(0);
    }

    [Fact]
    public async Task Sessions_Logout_ViaHttp()
    {
        var sessionService = new SessionService(_fx.Redb);
        var coreUser = await _fx.Redb.UserProvider.GetUserByLoginAsync(ProductionHttpFixture.TestUsername)
            ?? throw new Exception("Test user not found");
        var app = await _fx.Redb.Query<ApplicationProps>()
            .WhereRedb(o => o.ValueString == ProductionHttpFixture.TestClientId)
            .FirstOrDefaultAsync();

        await sessionService.CreateAsync(coreUser.Id, app!.id);

        // Logout via management HTTP
        var req = WithAuth(new HttpRequestMessage(HttpMethod.Post,
            $"/api/v1/identity/sessions/logout?userId={coreUser.Id}"));
        var resp = await _http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.OK);

        var json = await ParseJson(resp);
        json.GetProperty("success").GetBoolean().Should().BeTrue();
    }

    private static async Task<JsonElement> ParseJson(HttpResponseMessage resp)
    {
        var body = await resp.Content.ReadAsStringAsync();
        return JsonDocument.Parse(body).RootElement;
    }
}
