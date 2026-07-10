using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// E2E tests for user profile management via Management REST API.
/// Validates Address, CustomClaims, verification flags, and External fields
/// through the full HTTP pipeline: Kestrel → bearer auth → controller → direct-vm → processor → PostgreSQL.
/// </summary>
[Collection("ProductionHttp")]
public class UserProfileManagementTests
{
    private readonly ProductionHttpFixture _fx;
    private readonly HttpClient _http;
    private static readonly JsonSerializerOptions CamelCase = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    public UserProfileManagementTests(ProductionHttpFixture fx)
    {
        _fx = fx;
        _http = fx.Http;
    }

    private HttpRequestMessage Auth(HttpRequestMessage req)
    {
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fx.ManagementToken);
        return req;
    }

    private static async Task<JsonElement> ParseResponse(HttpResponseMessage resp, string context)
    {
        var body = await resp.Content.ReadAsStringAsync();
        resp.StatusCode.Should().Be(HttpStatusCode.OK, $"{context}: {body}");
        return JsonDocument.Parse(body).RootElement;
    }

    private static long GetId(JsonElement el)
    {
        if (el.TryGetProperty("id", out var v)) return v.GetInt64();
        if (el.TryGetProperty("Id", out v)) return v.GetInt64();
        throw new InvalidOperationException($"No 'id' in response: {el}");
    }

    private async Task<(long Id, string Login)> CreateUser(string? prefix = null)
    {
        var login = $"{prefix ?? "profile"}-{Guid.NewGuid():N}";
        var req = Auth(new HttpRequestMessage(HttpMethod.Post, "/api/v1/identity/users")
        {
            Content = JsonContent.Create(new
            {
                login,
                password = "P@ssw0rd123!",
                email = $"{login}@test.com",
                phoneNumber = "+79001234567"
            }, options: CamelCase)
        });
        var resp = await _http.SendAsync(req);
        var json = await ParseResponse(resp, "create");
        return (GetId(json), login);
    }

    private async Task<JsonElement> ReadUser(long id)
    {
        var req = Auth(new HttpRequestMessage(HttpMethod.Get, $"/api/v1/identity/users/{id}"));
        var resp = await _http.SendAsync(req);
        return await ParseResponse(resp, "read");
    }

    private async Task<JsonElement> UpdateUser(long id, object body)
    {
        var req = Auth(new HttpRequestMessage(HttpMethod.Put, $"/api/v1/identity/users/{id}")
        {
            Content = JsonContent.Create(body, options: CamelCase)
        });
        var resp = await _http.SendAsync(req);
        return await ParseResponse(resp, "update");
    }

    // ══════════════════════════════════════════════
    //  Newly-created user has null profile extensions
    // ══════════════════════════════════════════════

    [Fact]
    public async Task NewUser_ProfileFieldsDefaultToNull()
    {
        var (id, _) = await CreateUser("defaults");

        var user = await ReadUser(id);

        GetBool(user, "emailVerified").Should().BeFalse();
        GetBool(user, "phoneNumberVerified").Should().BeFalse();
        GetNullableString(user, "externalProvider").Should().BeNull();
        GetNullableString(user, "externalId").Should().BeNull();
        AssertPropertyNullOrMissing(user, "address");
        AssertPropertyNullOrMissing(user, "customClaims");
    }

    // ══════════════════════════════════════════════
    //  Update Address via PUT
    // ══════════════════════════════════════════════

    [Fact]
    public async Task UpdateAddress_RoundTrips()
    {
        var (id, _) = await CreateUser("addr");

        // Update with full OIDC address
        await UpdateUser(id, new
        {
            id,
            address = new
            {
                streetAddress = "123 Main St, Apt 4B",
                locality = "Springfield",
                region = "IL",
                postalCode = "62701",
                country = "US",
                formatted = "123 Main St, Apt 4B\nSpringfield, IL 62701\nUS"
            }
        });

        // Read back and verify
        var user = await ReadUser(id);
        var addr = Prop(user, "address")!.Value;
        GetNullableString(addr, "streetAddress").Should().Be("123 Main St, Apt 4B");
        GetNullableString(addr, "locality").Should().Be("Springfield");
        GetNullableString(addr, "region").Should().Be("IL");
        GetNullableString(addr, "postalCode").Should().Be("62701");
        GetNullableString(addr, "country").Should().Be("US");
        GetNullableString(addr, "formatted").Should().Contain("Springfield");
    }

    // ══════════════════════════════════════════════
    //  Update verification flags (Lk scenario)
    // ══════════════════════════════════════════════

    [Fact]
    public async Task UpdateVerificationFlags_ViaManagementApi()
    {
        var (id, _) = await CreateUser("verify");

        // Lk scenario: service confirms user's email → sets email_verified via Management API
        await UpdateUser(id, new
        {
            id,
            emailVerified = true,
            phoneNumberVerified = true
        });

        var user = await ReadUser(id);
        GetBool(user, "emailVerified").Should().BeTrue();
        GetBool(user, "phoneNumberVerified").Should().BeTrue();
    }

    // ══════════════════════════════════════════════
    //  Update CustomClaims — set and merge
    // ══════════════════════════════════════════════

    [Fact]
    public async Task UpdateCustomClaims_SetAndReadBack()
    {
        var (id, _) = await CreateUser("claims");

        await UpdateUser(id, new
        {
            id,
            customClaims = new Dictionary<string, string>
            {
                ["department"] = "Engineering",
                ["employee_id"] = "EMP-42"
            }
        });

        var user = await ReadUser(id);
        var claims = Prop(user, "customClaims")!.Value;
        GetNullableString(claims, "department").Should().Be("Engineering");
        GetNullableString(claims, "employee_id").Should().Be("EMP-42");
    }

    [Fact]
    public async Task UpdateCustomClaims_MergeSemanticsPreservesExisting()
    {
        var (id, _) = await CreateUser("merge");

        // First update: set A + B
        await UpdateUser(id, new
        {
            id,
            customClaims = new Dictionary<string, string>
            {
                ["role"] = "admin",
                ["tier"] = "gold"
            }
        });

        // Second update: change B + add C — should preserve A
        await UpdateUser(id, new
        {
            id,
            customClaims = new Dictionary<string, string>
            {
                ["tier"] = "platinum",
                ["region"] = "EU"
            }
        });

        var user = await ReadUser(id);
        var claims = Prop(user, "customClaims")!.Value;
        GetNullableString(claims, "role").Should().Be("admin", "A should be preserved");
        GetNullableString(claims, "tier").Should().Be("platinum", "B should be overwritten");
        GetNullableString(claims, "region").Should().Be("EU", "C should be added");
    }

    // ══════════════════════════════════════════════
    //  Full profile update in one PUT
    // ══════════════════════════════════════════════

    [Fact]
    public async Task FullProfileUpdate_AddressClaimsAndFlags()
    {
        var (id, _) = await CreateUser("full");

        var updated = await UpdateUser(id, new
        {
            id,
            givenName = "John",
            familyName = "Smith",
            emailVerified = true,
            phoneNumberVerified = true,
            address = new
            {
                streetAddress = "42 Main Street",
                locality = "London",
                country = "GB"
            },
            customClaims = new Dictionary<string, string>
            {
                ["org"] = "Acme Corp",
                ["level"] = "senior"
            }
        });

        // Verify all fields in the response from the update itself
        GetNullableString(updated, "givenName").Should().Be("John");
        GetNullableString(updated, "familyName").Should().Be("Smith");
        GetBool(updated, "emailVerified").Should().BeTrue();
        GetBool(updated, "phoneNumberVerified").Should().BeTrue();

        var addr = Prop(updated, "address")!.Value;
        GetNullableString(addr, "streetAddress").Should().Be("42 Main Street");
        GetNullableString(addr, "locality").Should().Be("London");
        GetNullableString(addr, "country").Should().Be("GB");

        var claims = Prop(updated, "customClaims")!.Value;
        GetNullableString(claims, "org").Should().Be("Acme Corp");
        GetNullableString(claims, "level").Should().Be("senior");

        // Also verify via separate GET to confirm persistence
        var readback = await ReadUser(id);
        GetBool(readback, "emailVerified").Should().BeTrue();
        GetNullableString(Prop(readback, "address")!.Value, "country").Should().Be("RU");
        GetNullableString(Prop(readback, "customClaims")!.Value, "org").Should().Be("Acme Corp");
    }

    // ══════════════════════════════════════════════
    //  ExternalIdentities are null for local users
    // ══════════════════════════════════════════════

    [Fact]
    public async Task LocalUser_ExternalFieldsAreNull()
    {
        var (id, _) = await CreateUser("local");

        // Even after profile updates, external fields stay null for locally-created users
        await UpdateUser(id, new
        {
            id,
            emailVerified = true,
            customClaims = new Dictionary<string, string> { ["test"] = "value" }
        });

        var user = await ReadUser(id);
        var extId = Prop(user, "externalIdentities");
        (extId is null || extId.Value.ValueKind == System.Text.Json.JsonValueKind.Null).Should().BeTrue(
            "local users should not have external identities");
    }

    // ══════════════════════════════════════════════
    //  GivenName + FamilyName via Management API
    // ══════════════════════════════════════════════

    [Fact]
    public async Task UpdateNameFields_ViaManagementApi()
    {
        var (id, _) = await CreateUser("names");

        await UpdateUser(id, new
        {
            id,
            givenName = "Alice",
            familyName = "Smith",
            picture = "https://example.com/avatar.jpg"
        });

        var user = await ReadUser(id);
        GetNullableString(user, "givenName").Should().Be("Alice");
        GetNullableString(user, "familyName").Should().Be("Smith");
        GetNullableString(user, "picture").Should().Be("https://example.com/avatar.jpg");
    }

    // ══════════════════════════════════════════════
    //  Helpers
    // ══════════════════════════════════════════════

    private static JsonElement? Prop(JsonElement el, string name)
    {
        // Try camelCase first, then PascalCase
        if (el.TryGetProperty(name, out var v)) return v;
        var pascal = char.ToUpper(name[0]) + name[1..];
        if (el.TryGetProperty(pascal, out v)) return v;
        return null;
    }

    private static string? GetNullableString(JsonElement el, string prop)
    {
        var v = Prop(el, prop);
        if (v is null || v.Value.ValueKind == JsonValueKind.Null) return null;
        return v.Value.GetString();
    }

    private static bool GetBool(JsonElement el, string prop)
    {
        var v = Prop(el, prop);
        return v?.GetBoolean() ?? false;
    }

    private static void AssertPropertyNullOrMissing(JsonElement el, string prop)
    {
        var v = Prop(el, prop);
        if (v is not null)
            v.Value.ValueKind.Should().Be(JsonValueKind.Null,
                $"'{prop}' should be null if present");
    }
}
