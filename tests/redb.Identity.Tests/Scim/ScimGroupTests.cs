using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using redb.Identity.Contracts.Scim;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Scim;

/// <summary>
/// SCIM 2.0 Groups endpoint integration tests (RFC 7644 §3).
/// </summary>
[Collection("ProductionHttp")]
public class ScimGroupTests
{
    private readonly ProductionHttpFixture _f;
    private readonly HttpClient _http;

    public ScimGroupTests(ProductionHttpFixture fixture)
    {
        _f = fixture;
        _http = fixture.Http;
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

    private static async Task<JsonElement> ReadJson(HttpResponseMessage response)
    {
        var stream = await response.Content.ReadAsStreamAsync();
        return await JsonSerializer.DeserializeAsync<JsonElement>(stream);
    }

    // ── Create user helper ──────────────────────────────────────

    private async Task<string> CreateTestUser(string? suffix = null)
    {
        var userName = $"scim-grp-usr-{suffix ?? Guid.NewGuid().ToString("N")}";
        var res = await _http.SendAsync(ScimPost("/scim/v2/Users",
            new ScimUser { UserName = userName, Active = true }));
        var json = await ReadJson(res);
        return json.GetProperty("id").GetString()!;
    }

    // ── CRUD ────────────────────────────────────────────────────

    [Fact]
    public async Task CreateGroup_ReturnsScimGroup()
    {
        var group = new ScimGroup
        {
            DisplayName = $"scim-group-{Guid.NewGuid():N}"
        };

        var res = await _http.SendAsync(ScimPost("/scim/v2/Groups", group));
        Assert.Equal(HttpStatusCode.Created, res.StatusCode);

        var json = await ReadJson(res);
        Assert.Equal(group.DisplayName, json.GetProperty("displayName").GetString());
        Assert.NotNull(json.GetProperty("id").GetString());
        Assert.Equal("Group", json.GetProperty("meta").GetProperty("resourceType").GetString());
    }

    [Fact]
    public async Task ReadGroup_ReturnsGroup()
    {
        // Create
        var displayName = $"scim-read-grp-{Guid.NewGuid():N}";
        var createRes = await _http.SendAsync(ScimPost("/scim/v2/Groups",
            new ScimGroup { DisplayName = displayName }));
        var created = await ReadJson(createRes);
        var id = created.GetProperty("id").GetString();

        // Read
        var res = await _http.SendAsync(ScimGet($"/scim/v2/Groups/{id}"));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var json = await ReadJson(res);
        Assert.Equal(id, json.GetProperty("id").GetString());
        Assert.Equal(displayName, json.GetProperty("displayName").GetString());
    }

    [Fact]
    public async Task ReadGroup_NotFound_Returns404()
    {
        var res = await _http.SendAsync(ScimGet("/scim/v2/Groups/999999"));
        Assert.Equal(HttpStatusCode.NotFound, res.StatusCode);
    }

    [Fact]
    public async Task ListGroups_ReturnsPaginatedList()
    {
        var res = await _http.SendAsync(ScimGet("/scim/v2/Groups?startIndex=1&count=10"));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var json = await ReadJson(res);
        Assert.True(json.GetProperty("totalResults").GetInt32() >= 0);
        Assert.Equal(1, json.GetProperty("startIndex").GetInt32());
    }

    [Fact]
    public async Task FilterGroups_ByDisplayName_ReturnsMatch()
    {
        var displayName = $"scim-flt-grp-{Guid.NewGuid():N}";
        await _http.SendAsync(ScimPost("/scim/v2/Groups",
            new ScimGroup { DisplayName = displayName }));

        var res = await _http.SendAsync(
            ScimGet($"/scim/v2/Groups?filter=displayName eq \"{displayName}\""));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var json = await ReadJson(res);
        Assert.Equal(1, json.GetProperty("totalResults").GetInt32());
        Assert.Equal(displayName, json.GetProperty("Resources")[0].GetProperty("displayName").GetString());
    }

    // ── Replace (PUT) ───────────────────────────────────────────

    [Fact]
    public async Task ReplaceGroup_UpdatesNameAndMembers()
    {
        // Create group + user
        var displayName = $"scim-replace-grp-{Guid.NewGuid():N}";
        var createRes = await _http.SendAsync(ScimPost("/scim/v2/Groups",
            new ScimGroup { DisplayName = displayName }));
        var created = await ReadJson(createRes);
        var groupId = created.GetProperty("id").GetString();

        var userId = await CreateTestUser();

        // Replace
        var newName = $"Replaced Group {Guid.NewGuid():N}";
        var replacement = new ScimGroup
        {
            Id = groupId,
            DisplayName = newName,
            Members = [new ScimMemberRef { Value = userId }]
        };
        var res = await _http.SendAsync(ScimPut($"/scim/v2/Groups/{groupId}", replacement));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var json = await ReadJson(res);
        Assert.Equal(newName, json.GetProperty("displayName").GetString());

        // Verify members were persisted in the response
        Assert.True(json.TryGetProperty("members", out var members), "Response should contain members");
        Assert.Equal(JsonValueKind.Array, members.ValueKind);
        Assert.True(members.GetArrayLength() >= 1, "Members array should have at least 1 entry");
        Assert.Equal(userId, members[0].GetProperty("value").GetString());
    }

    // ── PATCH ───────────────────────────────────────────────────

    [Fact]
    public async Task PatchGroup_RenameDisplayName()
    {
        var displayName = $"scim-patchdn-grp-{Guid.NewGuid():N}";
        var createRes = await _http.SendAsync(ScimPost("/scim/v2/Groups",
            new ScimGroup { DisplayName = displayName }));
        var created = await ReadJson(createRes);
        var groupId = created.GetProperty("id").GetString();

        var patchedName = $"Patched Group {Guid.NewGuid():N}";
        var patch = new ScimPatchRequest
        {
            Operations =
            [
                new ScimPatchOperation
                {
                    Op = "replace",
                    Path = "displayName",
                    Value = JsonSerializer.SerializeToElement(patchedName)
                }
            ]
        };
        var res = await _http.SendAsync(ScimPatch($"/scim/v2/Groups/{groupId}", patch));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var json = await ReadJson(res);
        Assert.Equal(patchedName, json.GetProperty("displayName").GetString());
    }

    [Fact]
    public async Task PatchGroup_AddMember()
    {
        // Create group + user
        var displayName = $"scim-patchmem-grp-{Guid.NewGuid():N}";
        var createRes = await _http.SendAsync(ScimPost("/scim/v2/Groups",
            new ScimGroup { DisplayName = displayName }));
        var created = await ReadJson(createRes);
        var groupId = created.GetProperty("id").GetString();

        var userId = await CreateTestUser();

        // Patch: add member
        var patch = new ScimPatchRequest
        {
            Operations =
            [
                new ScimPatchOperation
                {
                    Op = "add",
                    Path = "members",
                    Value = JsonSerializer.SerializeToElement(
                        new[] { new { value = userId } })
                }
            ]
        };
        var res = await _http.SendAsync(ScimPatch($"/scim/v2/Groups/{groupId}", patch));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        // Verify member present
        var readRes = await _http.SendAsync(ScimGet($"/scim/v2/Groups/{groupId}"));
        var readJson = await ReadJson(readRes);
        var members = readJson.GetProperty("members");
        Assert.True(members.GetArrayLength() > 0);
        Assert.Contains(userId,
            members.EnumerateArray().Select(m => m.GetProperty("value").GetString()));
    }

    [Fact]
    public async Task PatchGroup_RemoveMember()
    {
        // Create group + user
        var displayName = $"scim-rmmem-grp-{Guid.NewGuid():N}";
        var userId = await CreateTestUser();

        var createRes = await _http.SendAsync(ScimPost("/scim/v2/Groups",
            new ScimGroup
            {
                DisplayName = displayName,
                Members = [new ScimMemberRef { Value = userId }]
            }));
        var created = await ReadJson(createRes);
        var groupId = created.GetProperty("id").GetString();

        // Patch: remove member
        var patch = new ScimPatchRequest
        {
            Operations =
            [
                new ScimPatchOperation
                {
                    Op = "remove",
                    Path = $"members[value eq \"{userId}\"]"
                }
            ]
        };
        var res = await _http.SendAsync(ScimPatch($"/scim/v2/Groups/{groupId}", patch));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        // Verify member removed
        var readRes = await _http.SendAsync(ScimGet($"/scim/v2/Groups/{groupId}"));
        var readJson = await ReadJson(readRes);

        if (readJson.TryGetProperty("members", out var members))
        {
            Assert.DoesNotContain(userId,
                members.EnumerateArray().Select(m => m.GetProperty("value").GetString()));
        }
    }

    // ── Delete ──────────────────────────────────────────────────

    [Fact]
    public async Task DeleteGroup_Returns204()
    {
        var displayName = $"scim-del-grp-{Guid.NewGuid():N}";
        var createRes = await _http.SendAsync(ScimPost("/scim/v2/Groups",
            new ScimGroup { DisplayName = displayName }));
        var created = await ReadJson(createRes);
        var groupId = created.GetProperty("id").GetString();

        var res = await _http.SendAsync(ScimDelete($"/scim/v2/Groups/{groupId}"));
        Assert.Equal(HttpStatusCode.NoContent, res.StatusCode);

        // Confirm gone
        var readRes = await _http.SendAsync(ScimGet($"/scim/v2/Groups/{groupId}"));
        Assert.Equal(HttpStatusCode.NotFound, readRes.StatusCode);
    }

    // ── New integration tests (review fixes) ────────────────────

    [Fact]
    public async Task CreateGroup_Returns201WithLocationHeader()
    {
        var group = new ScimGroup { DisplayName = $"scim-201-grp-{Guid.NewGuid():N}" };
        var res = await _http.SendAsync(ScimPost("/scim/v2/Groups", group));

        Assert.Equal(HttpStatusCode.Created, res.StatusCode);
        Assert.NotNull(res.Headers.Location);
        Assert.Contains("/scim/v2/Groups/", res.Headers.Location!.ToString());
    }

    [Fact]
    public async Task CreateGroup_WithExternalId_PersistsExternalId()
    {
        var extId = Guid.NewGuid().ToString();
        var group = new ScimGroup
        {
            DisplayName = $"scim-extid-grp-{Guid.NewGuid():N}",
            ExternalId = extId
        };
        var res = await _http.SendAsync(ScimPost("/scim/v2/Groups", group));
        Assert.Equal(HttpStatusCode.Created, res.StatusCode);

        var json = await ReadJson(res);
        var groupId = json.GetProperty("id").GetString();

        // Re-read to verify persisted
        var readRes = await _http.SendAsync(ScimGet($"/scim/v2/Groups/{groupId}"));
        var readJson = await ReadJson(readRes);
        Assert.Equal(extId, readJson.GetProperty("externalId").GetString());
    }

    [Fact]
    public async Task GroupMembers_HaveDisplayName()
    {
        var userId = await CreateTestUser();

        var group = new ScimGroup
        {
            DisplayName = $"scim-display-grp-{Guid.NewGuid():N}",
            Members = [new ScimMemberRef { Value = userId }]
        };
        var res = await _http.SendAsync(ScimPost("/scim/v2/Groups", group));
        Assert.Equal(HttpStatusCode.Created, res.StatusCode);

        var json = await ReadJson(res);
        var members = json.GetProperty("members");
        Assert.True(members.GetArrayLength() > 0);

        var firstMember = members[0];
        Assert.True(firstMember.TryGetProperty("display", out var display));
        Assert.False(string.IsNullOrEmpty(display.GetString()));
    }

    // ── Extended filters (sw, co) ───────────────────────────────

    [Fact]
    public async Task FilterGroups_ByDisplayName_StartsWith()
    {
        var prefix = $"scim-grp-sw-{Guid.NewGuid():N}";
        await _http.SendAsync(ScimPost("/scim/v2/Groups",
            new ScimGroup { DisplayName = $"{prefix}-g1" }));

        var res = await _http.SendAsync(
            ScimGet($"/scim/v2/Groups?filter=displayName sw \"{prefix}\""));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var json = await ReadJson(res);
        Assert.True(json.GetProperty("totalResults").GetInt32() >= 1);
    }

    [Fact]
    public async Task FilterGroups_ByDisplayName_Contains()
    {
        var tag = Guid.NewGuid().ToString("N");
        await _http.SendAsync(ScimPost("/scim/v2/Groups",
            new ScimGroup { DisplayName = $"cotest-{tag}-group" }));

        var res = await _http.SendAsync(
            ScimGet($"/scim/v2/Groups?filter=displayName co \"{tag}\""));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var json = await ReadJson(res);
        Assert.True(json.GetProperty("totalResults").GetInt32() >= 1);
    }

    [Fact]
    public async Task FilterGroups_ByDisplayName_NotEqual()
    {
        var tag = Guid.NewGuid().ToString("N");
        var groupName = $"scim-ne-{tag}";
        await _http.SendAsync(ScimPost("/scim/v2/Groups",
            new ScimGroup { DisplayName = groupName }));

        // ne should return groups NOT matching the name
        var res = await _http.SendAsync(
            ScimGet($"/scim/v2/Groups?filter=displayName ne \"{groupName}\""));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var json = await ReadJson(res);
        // The created group should NOT be in results
        foreach (var r in json.GetProperty("Resources").EnumerateArray())
            Assert.NotEqual(groupName, r.GetProperty("displayName").GetString());
    }

    // ── ETag ────────────────────────────────────────────────────

    [Fact]
    public async Task ReadGroup_ReturnsETagInMeta()
    {
        var displayName = $"scim-grp-etag-{Guid.NewGuid():N}";
        var createRes = await _http.SendAsync(ScimPost("/scim/v2/Groups",
            new ScimGroup { DisplayName = displayName }));
        var created = await ReadJson(createRes);
        var id = created.GetProperty("id").GetString();

        var res = await _http.SendAsync(ScimGet($"/scim/v2/Groups/{id}"));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        // ETag header must be present and match meta.version
        Assert.True(res.Headers.Contains("ETag"), "Response should contain ETag header");
        var etag = res.Headers.ETag;
        Assert.NotNull(etag);

        var json = await ReadJson(res);
        var metaVersion = json.GetProperty("meta").GetProperty("version").GetString();
        Assert.NotNull(metaVersion);
        var fullETag = etag.IsWeak ? $"W/{etag.Tag}" : etag.Tag;
        Assert.Equal(metaVersion, fullETag);
    }

    [Fact]
    public async Task ReplaceGroup_WithWrongIfMatch_Returns412()
    {
        var displayName = $"scim-grp-412-{Guid.NewGuid():N}";
        var createRes = await _http.SendAsync(ScimPost("/scim/v2/Groups",
            new ScimGroup { DisplayName = displayName }));
        var created = await ReadJson(createRes);
        var id = created.GetProperty("id").GetString();

        var replacement = new ScimGroup { Id = id, DisplayName = $"Updated {displayName}" };
        var req = ScimPut($"/scim/v2/Groups/{id}", replacement);
        req.Headers.TryAddWithoutValidation("If-Match", "W/\"00000000-0000-0000-0000-000000000000\"");

        var res = await _http.SendAsync(req);
        Assert.Equal(HttpStatusCode.PreconditionFailed, res.StatusCode);
    }
}
