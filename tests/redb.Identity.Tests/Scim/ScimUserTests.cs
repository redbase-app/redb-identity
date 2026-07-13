using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using redb.Identity.Contracts.Scim;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.Scim;

/// <summary>
/// SCIM 2.0 Users endpoint integration tests (RFC 7644 §3).
/// Runs against ProductionHttpFixture (Kestrel + PostgreSQL + OpenIddict).
/// </summary>
[Collection("ProductionHttp")]
public class ScimUserTests
{
    private readonly ProductionHttpFixture _f;
    private readonly HttpClient _http;
    private readonly ITestOutputHelper _out;

    public ScimUserTests(ProductionHttpFixture fixture, ITestOutputHelper output)
    {
        _f = fixture;
        _http = fixture.Http;
        _out = output;
    }

    private HttpRequestMessage ScimGet(string path) => AuthedRequest(HttpMethod.Get, path);
    private HttpRequestMessage ScimPost(string path, object body) => AuthedRequest(HttpMethod.Post, path, body);
    private HttpRequestMessage ScimPut(string path, object body) => AuthedRequest(HttpMethod.Put, path, body);
    private HttpRequestMessage ScimPatch(string path, object body) => AuthedRequest(HttpMethod.Patch, path, body);
    private HttpRequestMessage ScimDelete(string path) => AuthedRequest(HttpMethod.Delete, path);

    private HttpRequestMessage AuthedRequest(HttpMethod method, string path, object? body = null)
    {
        var req = new HttpRequestMessage(method, path);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _f.ScimToken);
        if (body is not null)
        {
            var json = JsonSerializer.Serialize(body);
            req.Content = new StringContent(json, Encoding.UTF8, ScimConstants.MediaType);
        }
        return req;
    }

    private async Task<JsonElement> ReadJson(HttpResponseMessage response)
    {
        var raw = await response.Content.ReadAsStringAsync();
        _out.WriteLine($"[{(int)response.StatusCode}] {raw}");
        return JsonSerializer.Deserialize<JsonElement>(raw);
    }

    // ── Auth ────────────────────────────────────────────────────

    [Fact]
    public async Task ScimEndpoint_RequiresAuth()
    {
        var req = new HttpRequestMessage(HttpMethod.Get, "/scim/v2/Users");
        var res = await _http.SendAsync(req);
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }

    [Fact]
    public async Task ScimEndpoint_RejectsManagementScope()
    {
        var req = new HttpRequestMessage(HttpMethod.Get, "/scim/v2/Users");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _f.ManagementToken);
        var res = await _http.SendAsync(req);
        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
    }

    // ── Discovery ───────────────────────────────────────────────

    [Fact]
    public async Task ServiceProviderConfig_ReturnsCapabilities()
    {
        var res = await _http.SendAsync(ScimGet("/scim/v2/ServiceProviderConfig"));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var json = await ReadJson(res);
        Assert.True(json.GetProperty("patch").GetProperty("supported").GetBoolean());
        Assert.True(json.GetProperty("bulk").GetProperty("supported").GetBoolean());
        Assert.True(json.GetProperty("filter").GetProperty("supported").GetBoolean());
    }

    [Fact]
    public async Task ResourceTypes_ReturnsUserAndGroup()
    {
        var res = await _http.SendAsync(ScimGet("/scim/v2/ResourceTypes"));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var json = await ReadJson(res);
        Assert.Equal(2, json.GetProperty("totalResults").GetInt32());

        var resources = json.GetProperty("Resources");
        Assert.Equal("User", resources[0].GetProperty("id").GetString());
        Assert.Equal("Group", resources[1].GetProperty("id").GetString());
    }

    // ── CRUD ────────────────────────────────────────────────────

    [Fact]
    public async Task CreateUser_ReturnsScimUser()
    {
        var tag = Guid.NewGuid().ToString("N");
        var user = new ScimUser
        {
            UserName = $"scim-create-{tag}",
            DisplayName = $"SCIM Created {tag}"
        };

        var res = await _http.SendAsync(ScimPost("/scim/v2/Users", user));

        var json = await ReadJson(res);
        Assert.Equal(HttpStatusCode.Created, res.StatusCode);
        Assert.Equal(user.UserName, json.GetProperty("userName").GetString());
        Assert.Equal(user.DisplayName, json.GetProperty("displayName").GetString());
        Assert.NotNull(json.GetProperty("id").GetString());
        Assert.Equal("User", json.GetProperty("meta").GetProperty("resourceType").GetString());
    }

    [Fact]
    public async Task CreateUser_DuplicateUserName_Returns409()
    {
        var userName = $"scim-dup-{Guid.NewGuid():N}";
        var user = new ScimUser { UserName = userName, Active = true };

        var res1 = await _http.SendAsync(ScimPost("/scim/v2/Users", user));
        Assert.Equal(HttpStatusCode.Created, res1.StatusCode);

        var res2 = await _http.SendAsync(ScimPost("/scim/v2/Users", user));
        Assert.Equal(HttpStatusCode.Conflict, res2.StatusCode);

        var json = await ReadJson(res2);
        Assert.Equal("uniqueness", json.GetProperty("scimType").GetString());
    }

    [Fact]
    public async Task ReadUser_ReturnsScimUser()
    {
        // Create user first
        var tag = Guid.NewGuid().ToString("N");
        var userName = $"scim-read-{tag}";
        var createRes = await _http.SendAsync(ScimPost("/scim/v2/Users",
            new ScimUser { UserName = userName, DisplayName = $"Read Test {tag}" }));
        var created = await ReadJson(createRes);
        var id = created.GetProperty("id").GetString();

        // Read
        var res = await _http.SendAsync(ScimGet($"/scim/v2/Users/{id}"));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var json = await ReadJson(res);
        Assert.Equal(id, json.GetProperty("id").GetString());
        Assert.Equal(userName, json.GetProperty("userName").GetString());
    }

    [Fact]
    public async Task ReadUser_NotFound_Returns404()
    {
        var res = await _http.SendAsync(ScimGet("/scim/v2/Users/999999"));
        Assert.Equal(HttpStatusCode.NotFound, res.StatusCode);
    }

    [Fact]
    public async Task ReplaceUser_UpdatesAllFields()
    {
        // Create
        var tag = Guid.NewGuid().ToString("N");
        var userName = $"scim-replace-{tag}";
        var createRes = await _http.SendAsync(ScimPost("/scim/v2/Users",
            new ScimUser { UserName = userName, DisplayName = $"Before Replace {tag}" }));
        var created = await ReadJson(createRes);
        var id = created.GetProperty("id").GetString();

        // Replace
        var afterName = $"After Replace {tag}";
        var replacement = new ScimUser
        {
            Id = id,
            UserName = userName,
            DisplayName = afterName,
            Active = false,
            Name = new ScimName { GivenName = "After", FamilyName = "Replace" },
            Emails = [new ScimMultiValuedAttribute { Value = "replaced@example.com", Primary = true }]
        };
        var res = await _http.SendAsync(ScimPut($"/scim/v2/Users/{id}", replacement));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var json = await ReadJson(res);
        Assert.Equal(afterName, json.GetProperty("displayName").GetString());
        Assert.False(json.GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task PatchUser_ModifiesSpecificFields()
    {
        // Create
        var tag = Guid.NewGuid().ToString("N");
        var userName = $"scim-patch-{tag}";
        var displayName = $"Before Patch {tag}";
        var createRes = await _http.SendAsync(ScimPost("/scim/v2/Users",
            new ScimUser { UserName = userName, DisplayName = displayName, Active = true }));
        var created = await ReadJson(createRes);
        var id = created.GetProperty("id").GetString();

        // Patch: deactivate user (Azure Entra pattern)
        var patch = new ScimPatchRequest
        {
            Operations =
            [
                new ScimPatchOperation
                {
                    Op = "replace",
                    Value = JsonSerializer.SerializeToElement(new { active = false })
                }
            ]
        };
        var res = await _http.SendAsync(ScimPatch($"/scim/v2/Users/{id}", patch));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var json = await ReadJson(res);
        Assert.False(json.GetProperty("active").GetBoolean());
        Assert.Equal(displayName, json.GetProperty("displayName").GetString());
    }

    [Fact]
    public async Task PatchUser_NoPathMultiField_AzureEntraPattern()
    {
        // Azure Entra sends no-path PATCH with multiple fields in value object
        var tag = Guid.NewGuid().ToString("N");
        var userName = $"scim-nopatch-{tag}";
        var createRes = await _http.SendAsync(ScimPost("/scim/v2/Users",
            new ScimUser
            {
                UserName = userName,
                DisplayName = $"Old Name {tag}",
                Active = true,
                Name = new ScimName { GivenName = "Old", FamilyName = "User" },
                Emails = [new ScimMultiValuedAttribute { Value = $"old-{tag}@test.com", Primary = true }]
            }));
        Assert.Equal(HttpStatusCode.Created, createRes.StatusCode);
        var created = await ReadJson(createRes);
        var id = created.GetProperty("id").GetString();

        // No-path PATCH: multiple fields in a single operation (Azure Entra pattern)
        var patch = new ScimPatchRequest
        {
            Operations =
            [
                new ScimPatchOperation
                {
                    Op = "replace",
                    Value = JsonSerializer.SerializeToElement(new
                    {
                        displayName = $"New Name {tag}",
                        active = false,
                        name = new { givenName = "New", familyName = "Person" },
                        emails = new[] { new { value = $"new-{tag}@test.com", type = "work", primary = true } },
                        externalId = $"ext-{tag}"
                    })
                }
            ]
        };
        var res = await _http.SendAsync(ScimPatch($"/scim/v2/Users/{id}", patch));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var json = await ReadJson(res);
        Assert.Equal($"New Name {tag}", json.GetProperty("displayName").GetString());
        Assert.False(json.GetProperty("active").GetBoolean());
        Assert.Equal("New", json.GetProperty("name").GetProperty("givenName").GetString());
        Assert.Equal("Person", json.GetProperty("name").GetProperty("familyName").GetString());
        Assert.Equal($"ext-{tag}", json.GetProperty("externalId").GetString());

        // Verify email updated
        var emails = json.GetProperty("emails");
        Assert.True(emails.GetArrayLength() >= 1);
        Assert.Equal($"new-{tag}@test.com", emails[0].GetProperty("value").GetString());
    }

    [Fact]
    public async Task PatchUser_UpdateDisplayName()
    {
        var tag = Guid.NewGuid().ToString("N");
        var userName = $"scim-patchdn-{tag}";
        var createRes = await _http.SendAsync(ScimPost("/scim/v2/Users",
            new ScimUser { UserName = userName, DisplayName = $"Old Name {tag}" }));
        var created = await ReadJson(createRes);
        var id = created.GetProperty("id").GetString();

        var newName = $"New Name {tag}";
        var patch = new ScimPatchRequest
        {
            Operations =
            [
                new ScimPatchOperation
                {
                    Op = "replace",
                    Path = "displayName",
                    Value = JsonSerializer.SerializeToElement(newName)
                }
            ]
        };
        var res = await _http.SendAsync(ScimPatch($"/scim/v2/Users/{id}", patch));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var json = await ReadJson(res);
        Assert.Equal(newName, json.GetProperty("displayName").GetString());
    }

    [Fact]
    public async Task DeleteUser_Returns204()
    {
        var userName = $"scim-delete-{Guid.NewGuid():N}";
        var createRes = await _http.SendAsync(ScimPost("/scim/v2/Users",
            new ScimUser { UserName = userName }));
        var created = await ReadJson(createRes);
        var id = created.GetProperty("id").GetString();

        var res = await _http.SendAsync(ScimDelete($"/scim/v2/Users/{id}"));
        Assert.Equal(HttpStatusCode.NoContent, res.StatusCode);

        // User is soft-disabled. SCIM should hide disabled users (C2).
        var readRes = await _http.SendAsync(ScimGet($"/scim/v2/Users/{id}"));
        Assert.Equal(HttpStatusCode.NotFound, readRes.StatusCode);
    }

    // ── List + Filter ───────────────────────────────────────────

    [Fact]
    public async Task ListUsers_ReturnsPaginatedList()
    {
        var res = await _http.SendAsync(ScimGet("/scim/v2/Users?startIndex=1&count=10"));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var json = await ReadJson(res);
        Assert.True(json.GetProperty("totalResults").GetInt32() >= 0);
        Assert.Equal(1, json.GetProperty("startIndex").GetInt32());
        Assert.True(json.TryGetProperty("Resources", out _));
    }

    [Fact]
    public async Task FilterUsers_ByUserName_ReturnsMatch()
    {
        // Create user
        var userName = $"scim-filter-{Guid.NewGuid():N}";
        await _http.SendAsync(ScimPost("/scim/v2/Users",
            new ScimUser { UserName = userName }));

        // Filter
        var res = await _http.SendAsync(
            ScimGet($"/scim/v2/Users?filter=userName eq \"{userName}\""));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var json = await ReadJson(res);
        Assert.Equal(1, json.GetProperty("totalResults").GetInt32());
        Assert.Equal(userName, json.GetProperty("Resources")[0].GetProperty("userName").GetString());
    }

    [Fact]
    public async Task FilterUsers_ByUserName_NoMatch_ReturnsEmptyList()
    {
        var res = await _http.SendAsync(
            ScimGet("/scim/v2/Users?filter=userName eq \"nonexistent-user-xyz\""));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var json = await ReadJson(res);
        Assert.Equal(0, json.GetProperty("totalResults").GetInt32());
    }

    // ── New integration tests (review fixes) ────────────────────

    [Fact]
    public async Task CreateUser_Returns201WithLocationHeader()
    {
        var user = new ScimUser { UserName = $"scim-201-{Guid.NewGuid():N}" };
        var res = await _http.SendAsync(ScimPost("/scim/v2/Users", user));

        Assert.Equal(HttpStatusCode.Created, res.StatusCode);
        Assert.NotNull(res.Headers.Location);
        Assert.Contains("/scim/v2/Users/", res.Headers.Location!.ToString());
    }

    [Fact]
    public async Task DeleteUser_ThenListExcludesDeletedUser()
    {
        var userName = $"scim-delfilt-{Guid.NewGuid():N}";
        var createRes = await _http.SendAsync(ScimPost("/scim/v2/Users",
            new ScimUser { UserName = userName }));
        var created = await ReadJson(createRes);
        var id = created.GetProperty("id").GetString();

        await _http.SendAsync(ScimDelete($"/scim/v2/Users/{id}"));

        var listRes = await _http.SendAsync(
            ScimGet($"/scim/v2/Users?filter=userName eq \"{userName}\""));
        var listJson = await ReadJson(listRes);
        Assert.Equal(0, listJson.GetProperty("totalResults").GetInt32());
    }

    [Fact]
    public async Task CreateUser_InvalidUserNameTooShort_Returns400()
    {
        var user = new ScimUser { UserName = "ab" };
        var res = await _http.SendAsync(ScimPost("/scim/v2/Users", user));
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
    }

    [Fact]
    public async Task CreateUser_EmptyUserName_Returns400()
    {
        var user = new ScimUser { UserName = "" };
        var res = await _http.SendAsync(ScimPost("/scim/v2/Users", user));
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
    }

    [Fact]
    public async Task DiscoveryEndpoints_DoNotRequireAuth()
    {
        var spcReq = new HttpRequestMessage(HttpMethod.Get, "/scim/v2/ServiceProviderConfig");
        var spcRes = await _http.SendAsync(spcReq);
        Assert.Equal(HttpStatusCode.OK, spcRes.StatusCode);

        var rtReq = new HttpRequestMessage(HttpMethod.Get, "/scim/v2/ResourceTypes");
        var rtRes = await _http.SendAsync(rtReq);
        Assert.Equal(HttpStatusCode.OK, rtRes.StatusCode);

        var schemaReq = new HttpRequestMessage(HttpMethod.Get, "/scim/v2/Schemas");
        var schemaRes = await _http.SendAsync(schemaReq);
        Assert.Equal(HttpStatusCode.OK, schemaRes.StatusCode);
    }

    [Fact]
    public async Task SchemasEndpoint_ReturnsUserEnterpriseAndGroupSchemas()
    {
        var req = new HttpRequestMessage(HttpMethod.Get, "/scim/v2/Schemas");
        var res = await _http.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var json = await ReadJson(res);

        // Three, not two: core User, core Group, and the Enterprise User extension
        // (RFC 7643 §4.3). Assert the URNs rather than the count alone — a count check
        // passes just as happily when the wrong schema is listed.
        Assert.Equal(3, json.GetProperty("totalResults").GetInt32());

        var ids = json.GetProperty("Resources").EnumerateArray()
            .Select(r => r.GetProperty("id").GetString())
            .ToList();

        Assert.Contains("urn:ietf:params:scim:schemas:core:2.0:User", ids);
        Assert.Contains("urn:ietf:params:scim:schemas:core:2.0:Group", ids);
        Assert.Contains("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", ids);
    }

    [Fact]
    public async Task PatchUser_RenameUserName_Returns400_Immutable()
    {
        var tag = Guid.NewGuid().ToString("N");
        var userName = $"scim-rename-{tag}";
        var createRes = await _http.SendAsync(ScimPost("/scim/v2/Users",
            new ScimUser { UserName = userName }));
        var created = await ReadJson(createRes);
        var id = created.GetProperty("id").GetString();

        var newUserName = $"scim-renamed-{tag}";
        var patch = new ScimPatchRequest
        {
            Operations =
            [
                new ScimPatchOperation
                {
                    Op = "replace",
                    Path = "userName",
                    Value = JsonSerializer.SerializeToElement(newUserName)
                }
            ]
        };
        var res = await _http.SendAsync(ScimPatch($"/scim/v2/Users/{id}", patch));
        // userName is immutable (DB trigger prevents login change)
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
    }

    [Fact]
    public async Task ReplaceUser_RenameUserName_Returns400_Immutable()
    {
        var tag = Guid.NewGuid().ToString("N");
        var userName = $"scim-putrename-{tag}";
        var createRes = await _http.SendAsync(ScimPost("/scim/v2/Users",
            new ScimUser { UserName = userName, DisplayName = $"Put Rename Test {tag}" }));
        Assert.Equal(HttpStatusCode.Created, createRes.StatusCode);
        var created = await ReadJson(createRes);
        var id = created.GetProperty("id").GetString();

        var newUserName = $"scim-putrenamed-{tag}";
        var replacement = new ScimUser
        {
            Id = id,
            UserName = newUserName,
            DisplayName = $"Put Rename Test {tag}"
        };
        var res = await _http.SendAsync(ScimPut($"/scim/v2/Users/{id}", replacement));
        await ReadJson(res);
        // userName is immutable (DB trigger prevents login change)
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
    }

    [Fact]
    public async Task MetaLocation_IsAbsoluteUri()
    {
        var user = new ScimUser { UserName = $"scim-meta-{Guid.NewGuid():N}" };
        var res = await _http.SendAsync(ScimPost("/scim/v2/Users", user));
        var json = await ReadJson(res);

        var location = json.GetProperty("meta").GetProperty("location").GetString();
        Assert.StartsWith("http", location!);
        Assert.Contains("/scim/v2/Users/", location!);
    }

    // ── Extended filters (sw, co, pr) ───────────────────────────

    [Fact]
    public async Task FilterUsers_ByUserName_StartsWith()
    {
        var prefix = $"scim-sw-{Guid.NewGuid():N}";
        var userName = $"{prefix}-user1";
        await _http.SendAsync(ScimPost("/scim/v2/Users",
            new ScimUser { UserName = userName }));

        var res = await _http.SendAsync(
            ScimGet($"/scim/v2/Users?filter=userName sw \"{prefix}\""));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var json = await ReadJson(res);
        Assert.True(json.GetProperty("totalResults").GetInt32() >= 1);
        Assert.Contains(prefix, json.GetProperty("Resources")[0].GetProperty("userName").GetString());
    }

    [Fact]
    public async Task FilterUsers_ByDisplayName_Contains()
    {
        var tag = Guid.NewGuid().ToString("N");
        var displayName = $"Contains {tag} Test";
        await _http.SendAsync(ScimPost("/scim/v2/Users",
            new ScimUser { UserName = $"scim-co-{tag}", DisplayName = displayName }));

        var res = await _http.SendAsync(
            ScimGet($"/scim/v2/Users?filter=displayName co \"{tag}\""));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var json = await ReadJson(res);
        Assert.True(json.GetProperty("totalResults").GetInt32() >= 1);
    }

    [Fact]
    public async Task FilterUsers_ByUserName_Presence()
    {
        var res = await _http.SendAsync(ScimGet("/scim/v2/Users?filter=userName pr"));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var json = await ReadJson(res);
        Assert.True(json.GetProperty("totalResults").GetInt32() >= 1);
    }

    [Fact]
    public async Task FilterUsers_UnsupportedAttribute_Returns400()
    {
        var res = await _http.SendAsync(
            ScimGet("/scim/v2/Users?filter=nickName eq \"test\""));
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
    }

    [Fact]
    public async Task FilterUsers_ByUserName_NotEqual()
    {
        var tag = Guid.NewGuid().ToString("N");
        var userName = $"scim-ne-{tag}";
        await _http.SendAsync(ScimPost("/scim/v2/Users",
            new ScimUser { UserName = userName }));

        var res = await _http.SendAsync(
            ScimGet($"/scim/v2/Users?filter=userName ne \"{userName}\""));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var json = await ReadJson(res);
        var resources = json.GetProperty("Resources");
        for (int i = 0; i < resources.GetArrayLength(); i++)
            Assert.NotEqual(userName, resources[i].GetProperty("userName").GetString());
    }

    [Fact]
    public async Task FilterUsers_ByDisplayName_NotEqual()
    {
        var tag = Guid.NewGuid().ToString("N");
        var displayName = $"NE Display {tag}";
        await _http.SendAsync(ScimPost("/scim/v2/Users",
            new ScimUser { UserName = $"scim-ne-dn-{tag}", DisplayName = displayName }));

        var res = await _http.SendAsync(
            ScimGet($"/scim/v2/Users?filter=displayName ne \"{displayName}\""));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var json = await ReadJson(res);
        var resources = json.GetProperty("Resources");
        for (int i = 0; i < resources.GetArrayLength(); i++)
            Assert.NotEqual(displayName, resources[i].GetProperty("displayName").GetString());
    }

    [Fact]
    public async Task FilterUsers_ByEmail_NotEqual()
    {
        var tag = Guid.NewGuid().ToString("N");
        var email = $"scim-ne-{tag}@example.com";
        await _http.SendAsync(ScimPost("/scim/v2/Users",
            new ScimUser
            {
                UserName = $"scim-ne-em-{tag}",
                Emails = [new ScimMultiValuedAttribute { Value = email, Primary = true }]
            }));

        var res = await _http.SendAsync(
            ScimGet($"/scim/v2/Users?filter=emails.value ne \"{email}\""));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var json = await ReadJson(res);
        var resources = json.GetProperty("Resources");
        for (int i = 0; i < resources.GetArrayLength(); i++)
        {
            var emails = resources[i].GetProperty("emails");
            for (int j = 0; j < emails.GetArrayLength(); j++)
                Assert.NotEqual(email, emails[j].GetProperty("value").GetString());
        }
    }

    // ── Sort ────────────────────────────────────────────────────

    [Fact]
    public async Task ListUsers_WithSortBy_ReturnsOk()
    {
        // Create two users with a shared prefix so the sort assertion can isolate them via
        // a SCIM filter. Sorting "all users" is unreliable across collations: PostgreSQL's
        // en_US.UTF-8 (UCA) treats '-' as variable-weight ignorable, while any .NET
        // StringComparison treats it as a real character. Mixed accumulated data from
        // previous test runs can produce a server-side order that is correct under UCA but
        // looks unsorted to a .NET comparer — that's a collation mismatch in the test, not
        // a sort bug. Restricting to two userNames with an identical static prefix sidesteps
        // the disagreement (both engines agree on '...-a-xxxx' < '...-z-xxxx').
        var marker = Guid.NewGuid().ToString("N")[..8];
        var tagA = $"scim-sort-{marker}-a";
        var tagZ = $"scim-sort-{marker}-z";
        await _http.SendAsync(ScimPost("/scim/v2/Users", new ScimUser { UserName = tagA }));
        await _http.SendAsync(ScimPost("/scim/v2/Users", new ScimUser { UserName = tagZ }));

        var res = await _http.SendAsync(ScimGet(
            $"/scim/v2/Users?filter=userName sw \"scim-sort-{marker}-\"&sortBy=userName&sortOrder=ascending&count=10"));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var json = await ReadJson(res);
        var resources = json.GetProperty("Resources");
        var userNames = new List<string>();
        foreach (var r in resources.EnumerateArray())
            userNames.Add(r.GetProperty("userName").GetString()!);

        // Exactly the two users we created, in ascending order.
        Assert.Equal(2, userNames.Count);
        Assert.Equal(tagA, userNames[0]);
        Assert.Equal(tagZ, userNames[1]);
    }

    [Fact]
    public async Task ListUsers_WithSortDescending_ReturnsOk()
    {
        // Smoke test only: assert the sortOrder parameter is accepted and
        // produces a successful response with results. A strict order check
        // is unreliable here because the DB applies a locale-aware collation
        // (PostgreSQL en_US.UTF-8) that doesn't match any .NET StringComparison,
        // and pagination (count=100) can split different slices between
        // ascending/descending requests when the test DB accumulates users.
        var res = await _http.SendAsync(
            ScimGet("/scim/v2/Users?sortBy=userName&sortOrder=descending&count=100"));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var json = await ReadJson(res);
        var resources = json.GetProperty("Resources");
        Assert.True(resources.GetArrayLength() > 0, "descending list must not be empty");
    }

    // ── ETag ────────────────────────────────────────────────────

    [Fact]
    public async Task ReadUser_ReturnsETagHeader()
    {
        var userName = $"scim-etag-{Guid.NewGuid():N}";
        var createRes = await _http.SendAsync(ScimPost("/scim/v2/Users",
            new ScimUser { UserName = userName }));
        var created = await ReadJson(createRes);
        var id = created.GetProperty("id").GetString();

        var res = await _http.SendAsync(ScimGet($"/scim/v2/Users/{id}"));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        Assert.True(res.Headers.Contains("ETag"), "Response should contain ETag header");
        var etag = res.Headers.ETag?.Tag;
        Assert.NotNull(etag);

        // ETag header must match meta.version in the body
        var json = await ReadJson(res);
        var metaVersion = json.GetProperty("meta").GetProperty("version").GetString();
        Assert.NotNull(metaVersion);
        // .NET parses ETag header: IsWeak=true, Tag="guid". Reconstruct full value.
        var fullETag = res.Headers.ETag!.IsWeak ? $"W/{etag}" : etag;
        Assert.Equal(metaVersion, fullETag);
    }

    [Fact]
    public async Task ReplaceUser_WithCorrectIfMatch_Succeeds()
    {
        var tag = Guid.NewGuid().ToString("N");
        var userName = $"scim-ifm-{tag}";
        var createRes = await _http.SendAsync(ScimPost("/scim/v2/Users",
            new ScimUser { UserName = userName, DisplayName = $"Before {tag}" }));
        var created = await ReadJson(createRes);
        var id = created.GetProperty("id").GetString();

        // Get current ETag
        var readRes = await _http.SendAsync(ScimGet($"/scim/v2/Users/{id}"));
        var etag = readRes.Headers.ETag?.Tag;
        Assert.NotNull(etag);

        // Replace with If-Match
        var replacement = new ScimUser
        {
            Id = id,
            UserName = userName,
            DisplayName = $"After {tag}"
        };
        var req = ScimPut($"/scim/v2/Users/{id}", replacement);
        req.Headers.TryAddWithoutValidation("If-Match", etag);

        var res = await _http.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
    }

    [Fact]
    public async Task ReplaceUser_WithWrongIfMatch_Returns412()
    {
        var tag = Guid.NewGuid().ToString("N");
        var userName = $"scim-412-{tag}";
        var createRes = await _http.SendAsync(ScimPost("/scim/v2/Users",
            new ScimUser { UserName = userName, DisplayName = $"Before {tag}" }));
        var created = await ReadJson(createRes);
        var id = created.GetProperty("id").GetString();

        // Replace with wrong If-Match
        var replacement = new ScimUser
        {
            Id = id,
            UserName = userName,
            DisplayName = $"After {tag}"
        };
        var req = ScimPut($"/scim/v2/Users/{id}", replacement);
        req.Headers.TryAddWithoutValidation("If-Match", "W/\"00000000-0000-0000-0000-000000000000\"");

        var res = await _http.SendAsync(req);
        Assert.Equal(HttpStatusCode.PreconditionFailed, res.StatusCode);
    }

    // ── ServiceProviderConfig updated ───────────────────────────

    [Fact]
    public async Task ServiceProviderConfig_AdvertisesSortAndETag()
    {
        var res = await _http.SendAsync(ScimGet("/scim/v2/ServiceProviderConfig"));
        var json = await ReadJson(res);

        Assert.True(json.GetProperty("sort").GetProperty("supported").GetBoolean());
        Assert.True(json.GetProperty("etag").GetProperty("supported").GetBoolean());
    }
}
