using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// Full-stack E2E tests for the Management REST API.
/// Complete path: HTTP request → Kestrel → bearer auth → controller dispatch
/// → direct-vm:// → management processor → redb stores → PostgreSQL → response → HTTP.
/// Uses PRODUCTION OpenIddict (real stores, no degraded mode).
/// </summary>
[Collection("ProductionHttp")]
public class FullStackManagementTests
{
    private readonly ProductionHttpFixture _fx;
    private readonly HttpClient _http;

    public FullStackManagementTests(ProductionHttpFixture fx)
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

    // ══════════════════════════════════════════════
    //  Applications CRUD
    // ══════════════════════════════════════════════

    [Fact]
    public async Task Applications_CreateReadDelete_ViaHttp()
    {
        var clientId = $"e2e-crud-{Guid.NewGuid():N}";

        // Create
        var createReq = WithAuth(new HttpRequestMessage(HttpMethod.Post, "/api/v1/identity/applications")
        {
            Content = JsonContent.Create(new
            {
                clientId,
                clientSecret = "crud-test-secret",
                displayName = "E2E CRUD App"
            })
        });
        var createResp = await _http.SendAsync(createReq);
        createResp.StatusCode.Should().Be(HttpStatusCode.OK,
            "create failed: {0}", await createResp.Content.ReadAsStringAsync());
        var created = await ParseJson(createResp);

        // List — should contain the created app
        var listReq = WithAuth(new HttpRequestMessage(HttpMethod.Get, "/api/v1/identity/applications"));
        var listResp = await _http.SendAsync(listReq);
        listResp.StatusCode.Should().Be(HttpStatusCode.OK);

        // Delete
        var id = GetId(created);
        id.Should().NotBeNullOrEmpty("created app should have an id");

        var deleteReq = WithAuth(new HttpRequestMessage(HttpMethod.Delete,
            $"/api/v1/identity/applications/{id}"));
        var deleteResp = await _http.SendAsync(deleteReq);
        deleteResp.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    // ══════════════════════════════════════════════
    //  Users CRUD
    // ══════════════════════════════════════════════

    [Fact]
    public async Task Users_CreateAndList_ViaHttp()
    {
        var login = $"e2e-user-{Guid.NewGuid():N}";

        // Create
        var createReq = WithAuth(new HttpRequestMessage(HttpMethod.Post, "/api/v1/identity/users")
        {
            Content = JsonContent.Create(new
            {
                login,
                password = "Str0ng!Passw0rd"
            })
        });
        var createResp = await _http.SendAsync(createReq);
        createResp.StatusCode.Should().Be(HttpStatusCode.OK,
            "create user failed: {0}", await createResp.Content.ReadAsStringAsync());

        // List — should return 200
        var listReq = WithAuth(new HttpRequestMessage(HttpMethod.Get, "/api/v1/identity/users"));
        var listResp = await _http.SendAsync(listReq);
        listResp.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    // ══════════════════════════════════════════════
    //  Scopes CRUD
    // ══════════════════════════════════════════════

    [Fact]
    public async Task Scopes_CreateAndList_ViaHttp()
    {
        var scopeName = $"e2e-scope-{Guid.NewGuid():N}";

        // Create
        var createReq = WithAuth(new HttpRequestMessage(HttpMethod.Post, "/api/v1/identity/scopes")
        {
            Content = JsonContent.Create(new
            {
                name = scopeName,
                displayName = "E2E Test Scope"
            })
        });
        var createResp = await _http.SendAsync(createReq);
        createResp.StatusCode.Should().Be(HttpStatusCode.OK,
            "create scope failed: {0}", await createResp.Content.ReadAsStringAsync());

        // List
        var listReq = WithAuth(new HttpRequestMessage(HttpMethod.Get, "/api/v1/identity/scopes"));
        var listResp = await _http.SendAsync(listReq);
        listResp.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    // ══════════════════════════════════════════════
    //  Tokens
    // ══════════════════════════════════════════════

    [Fact]
    public async Task Tokens_ListAndPrune_ViaHttp()
    {
        // List
        var listReq = WithAuth(new HttpRequestMessage(HttpMethod.Get, "/api/v1/identity/tokens"));
        var listResp = await _http.SendAsync(listReq);
        listResp.StatusCode.Should().Be(HttpStatusCode.OK);

        // Prune
        var pruneReq = WithAuth(new HttpRequestMessage(HttpMethod.Post, "/api/v1/identity/tokens/prune"));
        var pruneResp = await _http.SendAsync(pruneReq);
        pruneResp.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    // ══════════════════════════════════════════════
    //  Bearer token enforcement
    // ══════════════════════════════════════════════

    [Fact]
    public async Task ManagementApi_NoBearerToken_Returns401()
    {
        var resp = await _http.GetAsync("/api/v1/identity/applications");
        resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task ManagementApi_InvalidBearerToken_Returns401()
    {
        var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/identity/applications");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "garbage-invalid-token");
        var resp = await _http.SendAsync(req);
        resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    // ══════════════════════════════════════════════
    //  404 — Not Found (non-existent resources)
    // ══════════════════════════════════════════════

    [Fact]
    public async Task Applications_GetNonExistent_ReturnsNotFound()
    {
        var resp = await SendAuth(HttpMethod.Get, "/api/v1/identity/applications/999999");

        resp.StatusCode.Should().Be(HttpStatusCode.NotFound);
        var json = await ParseJson(resp);
        json.GetProperty("error").GetString().Should().Be("not_found");
    }

    [Fact]
    public async Task Users_GetNonExistent_ReturnsNotFound()
    {
        var resp = await SendAuth(HttpMethod.Get, "/api/v1/identity/users/999999");

        resp.StatusCode.Should().Be(HttpStatusCode.NotFound);
        var json = await ParseJson(resp);
        json.GetProperty("error").GetString().Should().Be("not_found");
    }

    [Fact]
    public async Task Scopes_GetNonExistent_ReturnsNotFound()
    {
        var resp = await SendAuth(HttpMethod.Get, "/api/v1/identity/scopes/999999");

        resp.StatusCode.Should().Be(HttpStatusCode.NotFound);
        var json = await ParseJson(resp);
        json.GetProperty("error").GetString().Should().Be("not_found");
    }

    [Fact]
    public async Task Groups_GetNonExistent_ReturnsNotFound()
    {
        var resp = await SendAuth(HttpMethod.Get, "/api/v1/identity/groups/999999");

        resp.StatusCode.Should().Be(HttpStatusCode.NotFound);
        var json = await ParseJson(resp);
        json.GetProperty("error").GetString().Should().Be("not_found");
    }

    // ══════════════════════════════════════════════
    //  Duplicates
    // ══════════════════════════════════════════════

    [Fact]
    public async Task Applications_CreateDuplicate_ReturnsDuplicateError()
    {
        var clientId = $"e2e-dup-{Guid.NewGuid():N}";

        // First create
        await SendAuth(HttpMethod.Post, "/api/v1/identity/applications",
            new { clientId, displayName = "Dup Test" });

        // Second create with same clientId
        var resp = await SendAuth(HttpMethod.Post, "/api/v1/identity/applications",
            new { clientId, displayName = "Dup Test 2" });

        resp.StatusCode.Should().Be(HttpStatusCode.Conflict);
        var json = await ParseJson(resp);
        json.GetProperty("error").GetString().Should().Be("duplicate");
    }

    [Fact]
    public async Task Users_CreateDuplicate_ReturnsDuplicateError()
    {
        var login = $"e2e-dup-{Guid.NewGuid():N}";

        // First create
        await SendAuth(HttpMethod.Post, "/api/v1/identity/users",
            new { login, password = "Str0ng!Passw0rd" });

        // Second create with same login
        var resp = await SendAuth(HttpMethod.Post, "/api/v1/identity/users",
            new { login, password = "Str0ng!Passw0rd2" });

        resp.StatusCode.Should().Be(HttpStatusCode.Conflict);
        var json = await ParseJson(resp);
        json.GetProperty("error").GetString().Should().Be("duplicate");
    }

    [Fact]
    public async Task Scopes_CreateDuplicate_ReturnsDuplicateError()
    {
        var name = $"e2e-dup-{Guid.NewGuid():N}";

        // First create
        await SendAuth(HttpMethod.Post, "/api/v1/identity/scopes",
            new { name, displayName = "Dup Test" });

        // Second create with same name
        var resp = await SendAuth(HttpMethod.Post, "/api/v1/identity/scopes",
            new { name, displayName = "Dup Test 2" });

        resp.StatusCode.Should().Be(HttpStatusCode.Conflict);
        var json = await ParseJson(resp);
        json.GetProperty("error").GetString().Should().Be("duplicate");
    }

    // ══════════════════════════════════════════════
    //  Validation errors
    // ══════════════════════════════════════════════

    [Fact]
    public async Task Applications_CreateMissingClientId_ReturnsValidationError()
    {
        var resp = await SendAuth(HttpMethod.Post, "/api/v1/identity/applications",
            new { displayName = "No ClientId" });

        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var json = await ParseJson(resp);
        json.GetProperty("error").GetString().Should().Be("validation_error");
    }

    [Fact]
    public async Task Users_CreateEmptyLogin_ReturnsValidationError()
    {
        var resp = await SendAuth(HttpMethod.Post, "/api/v1/identity/users",
            new { login = "", password = "Str0ng!Passw0rd" });

        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var json = await ParseJson(resp);
        json.GetProperty("error").GetString().Should().Be("validation_error");
    }

    [Fact]
    public async Task Users_CreateEmptyPassword_ReturnsValidationError()
    {
        var resp = await SendAuth(HttpMethod.Post, "/api/v1/identity/users",
            new { login = "empty-pass-user", password = "" });

        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var json = await ParseJson(resp);
        json.GetProperty("error").GetString().Should().Be("validation_error");
    }

    [Fact]
    public async Task Scopes_CreateMissingName_ReturnsValidationError()
    {
        var resp = await SendAuth(HttpMethod.Post, "/api/v1/identity/scopes",
            new { displayName = "No Name" });

        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var json = await ParseJson(resp);
        json.GetProperty("error").GetString().Should().Be("validation_error");
    }

    [Fact]
    public async Task Tokens_RevokeNonExistent_ReturnsNotFound()
    {
        var resp = await SendAuth(HttpMethod.Delete, "/api/v1/identity/tokens/999999");

        resp.StatusCode.Should().Be(HttpStatusCode.NotFound);
        var json = await ParseJson(resp);
        json.GetProperty("error").GetString().Should().Be("not_found");
    }

    // ══════════════════════════════════════════════
    //  Helpers
    // ══════════════════════════════════════════════

    private async Task<HttpResponseMessage> SendAuth(HttpMethod method, string url, object? body = null)
    {
        var req = new HttpRequestMessage(method, url);
        req.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", _fx.ManagementToken);
        if (body is not null)
            req.Content = JsonContent.Create(body);
        return await _http.SendAsync(req);
    }

    private static async Task<JsonElement> ParseJson(HttpResponseMessage resp)
    {
        var body = await resp.Content.ReadAsStringAsync();
        return JsonDocument.Parse(body).RootElement;
    }

    private static string? GetId(JsonElement element)
    {
        if (element.TryGetProperty("id", out var id)) return id.ToString();
        if (element.TryGetProperty("Id", out id)) return id.ToString();
        return null;
    }
}
