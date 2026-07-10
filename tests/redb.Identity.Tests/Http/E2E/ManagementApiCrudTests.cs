using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Http.E2E;

/// <summary>
/// E2E test: Management REST API (CRUD) over real HTTP.
/// Uses <see cref="HttpIdentityFixture"/> with real PostgreSQL + Kestrel.
/// Exercises the full pipeline: HTTP → StripPrefix → Controller → direct-vm:// → processor → PostgreSQL.
/// </summary>
[Collection("HttpIdentity")]
public class ManagementApiCrudTests
{
    private readonly HttpIdentityFixture _fixture;
    private readonly HttpClient _http;

    public ManagementApiCrudTests(HttpIdentityFixture fixture)
    {
        _fixture = fixture;
        _http = fixture.Http;
    }

    private HttpRequestMessage WithAuth(HttpRequestMessage request)
    {
        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", _fixture.ManagementToken);
        return request;
    }

    // ── Applications ──

    [Fact]
    public async Task Applications_CrudLifecycle()
    {
        // Create
        var createReq = WithAuth(new HttpRequestMessage(HttpMethod.Post, "/api/v1/identity/applications")
        {
            Content = JsonContent.Create(new
            {
                clientId = $"crud-test-{Guid.NewGuid():N}",
                clientSecret = "test-secret",
                displayName = "CRUD Test App"
            })
        });
        var createResp = await _http.SendAsync(createReq);
        createResp.StatusCode.Should().Be(HttpStatusCode.OK,
            "create should succeed; body: {0}", await createResp.Content.ReadAsStringAsync());

        var created = await createResp.Content.ReadFromJsonAsync<JsonElement>();

        // List
        var listReq = WithAuth(new HttpRequestMessage(HttpMethod.Get, "/api/v1/identity/applications"));
        var listResp = await _http.SendAsync(listReq);
        listResp.StatusCode.Should().Be(HttpStatusCode.OK);

        // Delete (cleanup)
        var id = GetIdFromResponse(created);
        if (id is not null)
        {
            var deleteReq = WithAuth(new HttpRequestMessage(HttpMethod.Delete, $"/api/v1/identity/applications/{id}"));
            var deleteResp = await _http.SendAsync(deleteReq);
            deleteResp.StatusCode.Should().Be(HttpStatusCode.OK);
        }
    }

    // ── Scopes ──

    [Fact]
    public async Task Scopes_CrudLifecycle()
    {
        var scopeName = $"test-scope-{Guid.NewGuid():N}";

        // Create
        var createReq = WithAuth(new HttpRequestMessage(HttpMethod.Post, "/api/v1/identity/scopes")
        {
            Content = JsonContent.Create(new
            {
                name = scopeName,
                displayName = "Test Scope"
            })
        });
        var createResp = await _http.SendAsync(createReq);
        createResp.StatusCode.Should().Be(HttpStatusCode.OK,
            "create should succeed; body: {0}", await createResp.Content.ReadAsStringAsync());

        // List
        var listReq = WithAuth(new HttpRequestMessage(HttpMethod.Get, "/api/v1/identity/scopes"));
        var listResp = await _http.SendAsync(listReq);
        listResp.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    // ── Users ──

    [Fact]
    public async Task Users_CrudLifecycle()
    {
        var login = $"test-user-{Guid.NewGuid():N}";

        // Create
        var createReq = WithAuth(new HttpRequestMessage(HttpMethod.Post, "/api/v1/identity/users")
        {
            Content = JsonContent.Create(new
            {
                login,
                password = "P@ssw0rd123!"
            })
        });
        var createResp = await _http.SendAsync(createReq);
        createResp.StatusCode.Should().Be(HttpStatusCode.OK,
            "create should succeed; body: {0}", await createResp.Content.ReadAsStringAsync());

        // List
        var listReq = WithAuth(new HttpRequestMessage(HttpMethod.Get, "/api/v1/identity/users"));
        var listResp = await _http.SendAsync(listReq);
        listResp.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    // ── Tokens ──

    [Fact]
    public async Task Tokens_ListAndPrune()
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

    // ── Bearer token validation ──

    [Fact]
    public async Task ManagementApi_NoBearerToken_Returns401()
    {
        var response = await _http.GetAsync("/api/v1/identity/applications");
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task ManagementApi_InvalidBearerToken_Returns401()
    {
        var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/identity/applications");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "invalid-garbage-token");
        var response = await _http.SendAsync(req);
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    // ── Discovery ──

    [Fact]
    public async Task Discovery_ReturnsOpenIdConfiguration()
    {
        var response = await _http.GetAsync("/.well-known/openid-configuration");
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(body).RootElement;
        json.GetProperty("issuer").GetString().Should().Contain("localhost");
        json.TryGetProperty("token_endpoint", out _).Should().BeTrue(
            "discovery must include token_endpoint");
        json.TryGetProperty("grant_types_supported", out _).Should().BeTrue(
            "discovery must include grant_types_supported");
    }

    [Fact]
    public async Task Jwks_ReturnsKeySet()
    {
        var response = await _http.GetAsync("/.well-known/jwks");
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(body).RootElement;
        json.TryGetProperty("keys", out var keys).Should().BeTrue(
            "JWKS must contain 'keys' array");
        keys.ValueKind.Should().Be(JsonValueKind.Array,
            "'keys' must be a native JSON array");
        keys.GetArrayLength().Should().BeGreaterThan(0,
            "JWKS must contain at least one signing key");
    }

    private static string? GetIdFromResponse(JsonElement element)
    {
        if (element.TryGetProperty("id", out var id))
            return id.ToString();
        if (element.TryGetProperty("Id", out id))
            return id.ToString();
        return null;
    }

    // ── Rotate client_secret (W-3 follow-up) ──

    /// <summary>
    /// Happy path: create confidential client with secret S1, rotate via
    /// POST {id}/rotate-secret, then verify against the live store that
    /// (a) the response carries a non-empty <c>newSecret</c>,
    /// (b) the stored BCrypt hash of <c>ClientSecret</c> has changed (proves persistence
    ///     committed across the full HTTP → controller → direct-vm → processor → store path),
    /// (c) the new plaintext verifies against the new hash via the same OpenIddict
    ///     password hasher used by the token endpoint (proves the hash format is the one
    ///     credential validation expects, not a foreign encoding that would silently fail).
    /// <para>
    /// Why we do not POST <c>/connect/token</c> with the old/new secret in this test:
    /// <see cref="HttpIdentityFixture"/> runs OpenIddict in <c>EnableDegradedMode()</c>
    /// and short-circuits <c>ValidateTokenRequestContext</c>, so credential validation is
    /// bypassed entirely — any secret would succeed and the assertion would be meaningless.
    /// We assert against the storage layer instead.
    /// </para>
    /// </summary>
    [Fact]
    public async Task RotateSecret_returns_new_secret_and_changes_stored_hash()
    {
        var clientId = $"rotate-test-{Guid.NewGuid():N}";
        const string oldSecret = "S1-original-secret";

        var createReq = WithAuth(new HttpRequestMessage(HttpMethod.Post, "/api/v1/identity/applications")
        {
            Content = JsonContent.Create(new
            {
                clientId,
                clientSecret = oldSecret,
                clientType = "confidential",
                displayName = "Rotate-Test"
            })
        });
        var createResp = await _http.SendAsync(createReq);
        createResp.StatusCode.Should().Be(HttpStatusCode.OK,
            "create should succeed; body: {0}", await createResp.Content.ReadAsStringAsync());
        var id = GetIdFromResponse(await createResp.Content.ReadFromJsonAsync<JsonElement>())!;
        var numericId = long.Parse(id);

        try
        {
            // Snapshot the BCrypt hash that CreateAsync stored. We verify rotation by
            // checking this value changes — there is no way to recover plaintext from a
            // BCrypt digest, so this is the strongest property we can assert.
            var beforeApp = await _fixture.Redb.LoadAsync<redb.Identity.Core.Models.ApplicationProps>(numericId);
            beforeApp.Should().NotBeNull("the freshly created application must be loadable");
            var beforeHash = beforeApp!.Props.ClientSecret;
            beforeHash.Should().NotBeNullOrEmpty("create must have stored a hashed secret");

            // Rotate via the public HTTP API.
            var rotateReq = WithAuth(new HttpRequestMessage(
                HttpMethod.Post,
                $"/api/v1/identity/applications/{id}/rotate-secret"));
            var rotateResp = await _http.SendAsync(rotateReq);
            rotateResp.StatusCode.Should().Be(HttpStatusCode.OK,
                "rotate should succeed; body: {0}", await rotateResp.Content.ReadAsStringAsync());
            var rotated = await rotateResp.Content.ReadFromJsonAsync<JsonElement>();
            rotated.TryGetProperty("newSecret", out var newSecretProp).Should().BeTrue(
                "response must carry newSecret exactly once");
            var newSecret = newSecretProp.GetString();
            newSecret.Should().NotBeNullOrWhiteSpace();
            newSecret.Should().NotBe(oldSecret, "rotation must produce a different plaintext");

            // Re-load and confirm the stored hash actually changed in the database.
            var afterApp = await _fixture.Redb.LoadAsync<redb.Identity.Core.Models.ApplicationProps>(numericId);
            afterApp.Should().NotBeNull();
            var afterHash = afterApp!.Props.ClientSecret;
            afterHash.Should().NotBeNullOrEmpty("after rotation a hash must still be present");
            afterHash.Should().NotBe(beforeHash,
                "rotate must replace the stored hash; if these match the SaveAsync path is a no-op");

            // Verify the new plaintext verifies against the new hash through the SAME
            // OpenIddict pipeline the token endpoint uses for client_credentials. This
            // guards against a silent regression where rotation stores a hash in a format
            // (or with a salt) that ValidateClientSecretAsync cannot read back.
            using var verifyScope = _fixture.ServiceProvider.CreateScope();
            var manager = verifyScope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var entity = await manager.FindByIdAsync(id, default);
            entity.Should().NotBeNull();
            (await manager.ValidateClientSecretAsync(entity!, newSecret!, default))
                .Should().BeTrue("the freshly returned plaintext must verify against the freshly stored hash");
            (await manager.ValidateClientSecretAsync(entity!, oldSecret, default))
                .Should().BeFalse("the previous plaintext must no longer verify against the new hash");
        }
        finally
        {
            var deleteReq = WithAuth(new HttpRequestMessage(HttpMethod.Delete, $"/api/v1/identity/applications/{id}"));
            await _http.SendAsync(deleteReq);
        }
    }

    /// <summary>
    /// Public clients have no client_secret by definition (RFC 6749 §2.1) — rotation
    /// must reject them with HTTP 400 instead of silently generating a secret nobody
    /// can use at the token endpoint.
    /// </summary>
    [Fact]
    public async Task RotateSecret_rejects_public_client_with_400()
    {
        var clientId = $"rotate-public-{Guid.NewGuid():N}";
        var createReq = WithAuth(new HttpRequestMessage(HttpMethod.Post, "/api/v1/identity/applications")
        {
            Content = JsonContent.Create(new
            {
                clientId,
                clientType = "public",
                displayName = "Rotate-Public-Reject"
            })
        });
        var createResp = await _http.SendAsync(createReq);
        createResp.StatusCode.Should().Be(HttpStatusCode.OK,
            "create public client should succeed; body: {0}", await createResp.Content.ReadAsStringAsync());
        var id = GetIdFromResponse(await createResp.Content.ReadFromJsonAsync<JsonElement>())!;

        try
        {
            var rotateReq = WithAuth(new HttpRequestMessage(
                HttpMethod.Post,
                $"/api/v1/identity/applications/{id}/rotate-secret"));
            var rotateResp = await _http.SendAsync(rotateReq);
            rotateResp.StatusCode.Should().Be(HttpStatusCode.BadRequest,
                "public clients must be refused; body: {0}", await rotateResp.Content.ReadAsStringAsync());

            var body = await rotateResp.Content.ReadAsStringAsync();
            body.Should().Contain("invalid_client_type",
                "error code must let callers distinguish this from generic validation failures");
        }
        finally
        {
            var deleteReq = WithAuth(new HttpRequestMessage(HttpMethod.Delete, $"/api/v1/identity/applications/{id}"));
            await _http.SendAsync(deleteReq);
        }
    }
}
