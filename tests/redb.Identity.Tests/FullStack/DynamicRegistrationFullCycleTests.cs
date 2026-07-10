using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// Z1 + Z2 (RFC 7591 §3.2.1 + RFC 7592): Full-stack end-to-end cycle for Dynamic Client Registration.
/// <list type="number">
///   <item>POST <c>/connect/register</c> → client is created; response carries
///         <c>registration_access_token</c> + <c>registration_client_uri</c>.</item>
///   <item>GET <c>{registration_client_uri}</c> with the returned RAT → 200 + full metadata,
///         NEVER the <c>client_secret</c>.</item>
///   <item>GET with a wrong RAT → 401 <c>invalid_token</c>.</item>
///   <item>PUT <c>{registration_client_uri}</c> → 200 with mutated fields; subsequent GET reflects them.</item>
///   <item>DELETE <c>{registration_client_uri}</c> → 204; subsequent GET → 401 (client gone).</item>
/// </list>
/// </summary>
[Collection("ProductionHttp")]
public class DynamicRegistrationFullCycleTests
{
    private readonly ProductionHttpFixture _fx;
    private readonly HttpClient _http;

    public DynamicRegistrationFullCycleTests(ProductionHttpFixture fx)
    {
        _fx = fx;
        _http = fx.Http;
    }

    [Fact]
    public async Task Register_Read_Update_Delete_FullCycle()
    {
        // ── 1) REGISTER ──
        var regBody = new
        {
            redirect_uris = new[] { "https://initial.example.com/cb" },
            client_name = "Z1Z2 Cycle Test",
            token_endpoint_auth_method = "client_secret_basic"
        };
        var regReq = new HttpRequestMessage(HttpMethod.Post, "/connect/register")
        {
            Content = JsonContent.Create(regBody)
        };
        regReq.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", ProductionHttpFixture.DynamicRegAccessToken);

        var regResp = await _http.SendAsync(regReq);
        regResp.StatusCode.Should().Be(HttpStatusCode.Created,
            "register failed: {0}", await regResp.Content.ReadAsStringAsync());

        var regJson = await ParseJson(regResp);
        var clientId = regJson.GetProperty("client_id").GetString()!;
        var rat = regJson.GetProperty("registration_access_token").GetString()!;
        var uri = regJson.GetProperty("registration_client_uri").GetString()!;
        clientId.Should().NotBeNullOrWhiteSpace();
        rat.Should().NotBeNullOrWhiteSpace("RFC 7591 §3.2.1 — registration_access_token MUST be issued");
        uri.Should().StartWith($"http://localhost:{_fx.Port}/connect/register/");
        // Relative path for requests against the fixture's HttpClient.
        var mgmtPath = $"/connect/register/{Uri.EscapeDataString(clientId)}";

        // ── 2) READ with correct RAT ──
        var getResp = await SendAuthed(HttpMethod.Get, mgmtPath, rat);
        var getBody = await getResp.Content.ReadAsStringAsync();
        getResp.StatusCode.Should().Be(HttpStatusCode.OK,
            "GET with valid RAT must succeed: [{0}] body='{1}' path={2}", getResp.StatusCode, getBody, mgmtPath);
        // Diagnostic — if body is non-JSON, fail with actual value.
        getBody.TrimStart().Should().StartWith("{", "expected JSON response, got: '{0}'", getBody);
        var getJson = JsonDocument.Parse(getBody).RootElement;
        getJson.GetProperty("client_id").GetString().Should().Be(clientId);
        getJson.TryGetProperty("client_secret", out _).Should().BeFalse(
            "RFC 7592 §2.3 — client_secret MUST NOT be returned on management GET");
        getJson.TryGetProperty("registration_access_token", out _).Should().BeFalse(
            "RAT is one-shot at creation; management reads never echo it");
        getJson.GetProperty("redirect_uris").EnumerateArray().Select(e => e.GetString())
            .Should().Contain("https://initial.example.com/cb");

        // ── 3) READ with wrong RAT → 401 ──
        var badResp = await SendAuthed(HttpMethod.Get, mgmtPath, "wrong-token-value");
        badResp.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        var badJson = await ParseJson(badResp);
        badJson.GetProperty("error").GetString().Should().Be("invalid_token");

        // ── 4) UPDATE ──
        var putReq = new HttpRequestMessage(HttpMethod.Put, mgmtPath)
        {
            Content = JsonContent.Create(new
            {
                redirect_uris = new[] { "https://updated.example.com/cb" },
                client_name = "Z1Z2 Renamed"
            })
        };
        putReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", rat);
        var putResp = await _http.SendAsync(putReq);
        putResp.StatusCode.Should().Be(HttpStatusCode.OK,
            "PUT with valid RAT must succeed: {0}", await putResp.Content.ReadAsStringAsync());

        // Verify via read — mutations persisted.
        var verifyResp = await SendAuthed(HttpMethod.Get, mgmtPath, rat);
        verifyResp.StatusCode.Should().Be(HttpStatusCode.OK);
        var verifyJson = await ParseJson(verifyResp);
        verifyJson.GetProperty("client_name").GetString().Should().Be("Z1Z2 Renamed");
        verifyJson.GetProperty("redirect_uris").EnumerateArray().Select(e => e.GetString())
            .Should().BeEquivalentTo(new[] { "https://updated.example.com/cb" });

        // ── 5) DELETE ──
        var delResp = await SendAuthed(HttpMethod.Delete, mgmtPath, rat);
        delResp.StatusCode.Should().Be(HttpStatusCode.NoContent);

        // ── 6) Subsequent read → 401 (client not found, but surfaced as invalid_token per RFC 7592) ──
        var afterDel = await SendAuthed(HttpMethod.Get, mgmtPath, rat);
        afterDel.StatusCode.Should().BeOneOf(HttpStatusCode.Unauthorized, HttpStatusCode.NotFound);
    }

    private async Task<HttpResponseMessage> SendAuthed(HttpMethod method, string path, string bearer)
    {
        var req = new HttpRequestMessage(method, path);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return await _http.SendAsync(req);
    }

    private static async Task<JsonElement> ParseJson(HttpResponseMessage resp)
    {
        var body = await resp.Content.ReadAsStringAsync();
        return JsonDocument.Parse(body).RootElement;
    }
}
