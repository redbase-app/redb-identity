using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// H6 / H7 (v1.0 DoD): every well-formed Introspection / Revocation / Device-Authorization
/// request emits the expected entry in the audit catalog.
/// <para>
/// Path: HTTP → Kestrel → HTTP facade → core route → OpenIddict pipeline → WireTap →
/// EventDispatchProcessor → AuditEventSinkProcessor → PROPS → admin GET /audit query.
/// </para>
/// </summary>
[Collection("ProductionHttp")]
public class AuditCompletenessFullCycleTests
{
    private readonly ProductionHttpFixture _fx;
    private readonly HttpClient _http;

    public AuditCompletenessFullCycleTests(ProductionHttpFixture fx)
    {
        _fx = fx;
        _http = fx.Http;
    }

    // ══════════════════════════════════════════════
    //  H6 — Introspection (RFC 7662)
    // ══════════════════════════════════════════════

    [Fact]
    public async Task Introspection_EmitsTokenIntrospectedAuditEvent()
    {
        var token = await ObtainAccessTokenAsync();

        var resp = await _http.PostAsync("/connect/introspect", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = token,
            ["client_id"] = ProductionHttpFixture.TestClientId,
            ["client_secret"] = ProductionHttpFixture.TestClientSecret
        }));
        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            "RFC 7662 §2.2: introspection must answer 200 — got {0}: {1}",
            resp.StatusCode, await resp.Content.ReadAsStringAsync());

        await Task.Delay(2000);
        var rows = await QueryAuditAsync("TokenIntrospected");
        rows.Should().NotBeEmpty(
            "core processor must emit audit catalog event TokenIntrospected after a well-formed introspection");
    }

    // ══════════════════════════════════════════════
    //  H6 — Revocation (RFC 7009)
    // ══════════════════════════════════════════════

    [Fact]
    public async Task Revocation_EmitsTokenRevokedAuditEvent()
    {
        // Use refresh-token: RFC 7009 §2: introspectable & revocable for confidential clients.
        var (_, refresh) = await ObtainAccessAndRefreshAsync();

        var resp = await _http.PostAsync("/connect/revocation", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = refresh,
            ["token_type_hint"] = "refresh_token",
            ["client_id"] = ProductionHttpFixture.TestClientId,
            ["client_secret"] = ProductionHttpFixture.TestClientSecret
        }));
        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            "RFC 7009 §2.2: revocation must answer 200 — got {0}: {1}",
            resp.StatusCode, await resp.Content.ReadAsStringAsync());

        await Task.Delay(2000);
        var rows = await QueryAuditAsync("TokenRevoked");
        rows.Should().NotBeEmpty(
            "core processor must emit audit catalog event TokenRevoked after a well-formed revocation");
    }

    // ══════════════════════════════════════════════
    //  H7 — Device Authorization (RFC 8628)
    // ══════════════════════════════════════════════

    [Fact]
    public async Task DeviceAuthorization_EmitsDeviceCodeIssuedAuditEvent()
    {
        var resp = await _http.PostAsync("/connect/deviceauthorization", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = ProductionHttpFixture.TestPublicClientId,
            ["scope"] = "openid"
        }));
        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            "RFC 8628 §3.2: device authorization must answer 200 — got {0}: {1}",
            resp.StatusCode, await resp.Content.ReadAsStringAsync());

        await Task.Delay(2000);
        var rows = await QueryAuditAsync("DeviceCodeIssued");
        rows.Should().NotBeEmpty(
            "core processor must emit audit catalog event DeviceCodeIssued after issuing a device_code");
    }

    // ══════════════════════════════════════════════
    //  helpers
    // ══════════════════════════════════════════════

    private async Task<string> ObtainAccessTokenAsync()
    {
        var resp = await _http.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = ProductionHttpFixture.TestClientId,
            ["client_secret"] = ProductionHttpFixture.TestClientSecret,
            // 'groups' is registered globally by RedbIdentityServer and granted to TestClientId.
            ["scope"] = "groups"
        }));
        resp.IsSuccessStatusCode.Should().BeTrue(
            "obtain access token failed: {0}", await resp.Content.ReadAsStringAsync());
        var json = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        return json.GetProperty("access_token").GetString()!;
    }

    private async Task<(string Access, string Refresh)> ObtainAccessAndRefreshAsync()
    {
        var resp = await _http.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = ProductionHttpFixture.TestUsername,
            ["password"] = ProductionHttpFixture.TestPassword,
            ["client_id"] = ProductionHttpFixture.TestClientId,
            ["client_secret"] = ProductionHttpFixture.TestClientSecret,
            ["scope"] = "openid offline_access groups"
        }));
        resp.IsSuccessStatusCode.Should().BeTrue(
            "obtain refresh token failed: {0}", await resp.Content.ReadAsStringAsync());
        var json = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        return (
            json.GetProperty("access_token").GetString()!,
            json.GetProperty("refresh_token").GetString()!);
    }

    private async Task<List<JsonElement>> QueryAuditAsync(string eventType)
    {
        // Polling retry: GET /audit can transiently return 503 / "Database temporarily
        // unavailable" when the in-process audit pipeline is still flushing its
        // background INSERT batch onto the same NpgsqlConnection pool slot that the
        // /audit SELECT now wants. OnException<DbException> in IdentityCoreRouteBuilder
        // catches it and returns the 503 envelope; we poll a few times so a 100-200 ms
        // window of contention doesn't fail the test. Each attempt opens a fresh HTTP
        // request → fresh per-request DI scope → fresh connection from the pool.
        HttpResponseMessage? lastResp = null;
        string lastBody = string.Empty;
        for (var attempt = 0; attempt < 10; attempt++)
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, $"/api/v1/identity/audit?eventType={eventType}&count=50");
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fx.ManagementToken);
            lastResp = await _http.SendAsync(req);
            lastBody = await lastResp.Content.ReadAsStringAsync();
            if (lastResp.IsSuccessStatusCode)
            {
                var doc = JsonDocument.Parse(lastBody);
                return doc.RootElement.GetProperty("items").EnumerateArray().ToList();
            }
            await Task.Delay(300);
        }
        lastResp!.IsSuccessStatusCode.Should().BeTrue(
            "GET /audit failed after 10 attempts: {0} {1}", lastResp.StatusCode, lastBody);
        return new List<JsonElement>();
    }
}
