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
/// SCIM 2.0 Bulk endpoint integration tests (RFC 7644 §3.7 — H1).
/// Covers per-op dispatch, bulkId forward-reference resolution, and failOnErrors semantics.
/// </summary>
[Collection("ProductionHttp")]
public class ScimBulkTests
{
    private readonly ProductionHttpFixture _f;
    private readonly HttpClient _http;
    private readonly ITestOutputHelper _out;

    public ScimBulkTests(ProductionHttpFixture fixture, ITestOutputHelper output)
    {
        _f = fixture;
        _http = fixture.Http;
        _out = output;
    }

    private HttpRequestMessage AuthedPost(string path, object body)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, path);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _f.ScimToken);
        var json = JsonSerializer.Serialize(body);
        req.Content = new StringContent(json, Encoding.UTF8, ScimConstants.MediaType);
        return req;
    }

    private async Task<JsonElement> ReadJson(HttpResponseMessage response)
    {
        var raw = await response.Content.ReadAsStringAsync();
        _out.WriteLine($"[{(int)response.StatusCode}] {raw}");
        return JsonSerializer.Deserialize<JsonElement>(raw);
    }

    private static JsonElement AsJson(object value)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value);
        using var doc = JsonDocument.Parse(bytes);
        return doc.RootElement.Clone();
    }

    // ── Discovery ──

    [Fact]
    public async Task ServiceProviderConfig_AdvertisesBulkSupported()
    {
        var req = new HttpRequestMessage(HttpMethod.Get, "/scim/v2/ServiceProviderConfig");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _f.ScimToken);
        var res = await _http.SendAsync(req);
        var json = await ReadJson(res);
        Assert.True(json.GetProperty("bulk").GetProperty("supported").GetBoolean());
        Assert.Equal(1000, json.GetProperty("bulk").GetProperty("maxOperations").GetInt32());
    }

    // ── Happy path: create two users in one bulk request ──

    [Fact]
    public async Task Bulk_CreatesMultipleUsers_ReturnsAggregatedResponse()
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var request = new ScimBulkRequest
        {
            Operations =
            [
                new ScimBulkOperation
                {
                    Method = "POST", Path = "/Users", BulkId = "u1",
                    Data = AsJson(new ScimUser { UserName = $"bulk_a_{suffix}", Active = true })
                },
                new ScimBulkOperation
                {
                    Method = "POST", Path = "/Users", BulkId = "u2",
                    Data = AsJson(new ScimUser { UserName = $"bulk_b_{suffix}", Active = true })
                }
            ]
        };

        var res = await _http.SendAsync(AuthedPost("/scim/v2/Bulk", request));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        var json = await ReadJson(res);

        var ops = json.GetProperty("Operations");
        Assert.Equal(2, ops.GetArrayLength());
        Assert.Equal("201", ops[0].GetProperty("status").GetString());
        Assert.Equal("u1", ops[0].GetProperty("bulkId").GetString());
        Assert.Equal("201", ops[1].GetProperty("status").GetString());
        Assert.Contains("/scim/v2/Users/", ops[0].GetProperty("location").GetString()!);
    }

    // ── failOnErrors stops the stream ──

    [Fact]
    public async Task Bulk_StopsAfterFailOnErrorsThreshold()
    {
        // First op invalid (POST without data); second op should not run.
        var request = new ScimBulkRequest
        {
            FailOnErrors = 1,
            Operations =
            [
                new ScimBulkOperation { Method = "POST", Path = "/Users" /* no data */ },
                new ScimBulkOperation
                {
                    Method = "POST", Path = "/Users", BulkId = "u2",
                    Data = AsJson(new ScimUser
                    {
                        UserName = $"never_{Guid.NewGuid():N}", Active = true
                    })
                }
            ]
        };

        var res = await _http.SendAsync(AuthedPost("/scim/v2/Bulk", request));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        var json = await ReadJson(res);
        var ops = json.GetProperty("Operations");
        // Only the failing op should be present — second one is skipped per RFC §3.7.3.
        Assert.Equal(1, ops.GetArrayLength());
        Assert.Equal("400", ops[0].GetProperty("status").GetString());
    }

    // ── BulkId forward-reference resolution (RFC §3.7.2) ──

    [Fact]
    public async Task Bulk_ResolvesBulkIdReference_FromCreatedUser_IntoSubsequentGroupMembership()
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];

        // Op 1: create user with bulkId="member1".
        // Op 2: create group whose Members[].Value references "bulkId:member1".
        // The processor must rewrite the reference to the user's canonical location
        // before dispatching the group create.
        var groupData = JsonDocument.Parse($$"""
        {
            "schemas": ["{{ScimConstants.GroupSchema}}"],
            "displayName": "bulk_group_{{suffix}}",
            "members": [ { "value": "bulkId:member1", "type": "User" } ]
        }
        """).RootElement.Clone();

        var request = new ScimBulkRequest
        {
            Operations =
            [
                new ScimBulkOperation
                {
                    Method = "POST", Path = "/Users", BulkId = "member1",
                    Data = AsJson(new ScimUser { UserName = $"bulk_ref_{suffix}", Active = true })
                },
                new ScimBulkOperation
                {
                    Method = "POST", Path = "/Groups", BulkId = "g1",
                    Data = groupData
                }
            ]
        };

        var res = await _http.SendAsync(AuthedPost("/scim/v2/Bulk", request));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        var json = await ReadJson(res);

        var ops = json.GetProperty("Operations");
        Assert.Equal(2, ops.GetArrayLength());
        Assert.Equal("201", ops[0].GetProperty("status").GetString());
        Assert.Equal("201", ops[1].GetProperty("status").GetString());
    }

    // ── Unresolved bulkId → operation-level 409 ──

    [Fact]
    public async Task Bulk_RejectsUnresolvedBulkIdReference()
    {
        var groupData = JsonDocument.Parse($$"""
        {
            "schemas": ["{{ScimConstants.GroupSchema}}"],
            "displayName": "bulk_group_orphan_{{Guid.NewGuid():N}}",
            "members": [ { "value": "bulkId:doesNotExist", "type": "User" } ]
        }
        """).RootElement.Clone();

        var request = new ScimBulkRequest
        {
            Operations =
            [
                new ScimBulkOperation { Method = "POST", Path = "/Groups", BulkId = "g1", Data = groupData }
            ]
        };

        var res = await _http.SendAsync(AuthedPost("/scim/v2/Bulk", request));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        var json = await ReadJson(res);
        var ops = json.GetProperty("Operations");
        Assert.Equal("409", ops[0].GetProperty("status").GetString());
    }

    // ── DELETE op via bulk ──

    [Fact]
    public async Task Bulk_DeletesUser_ReturnsNoContentStatus()
    {
        // Create a user out of band, then delete it via bulk.
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var createReq = new HttpRequestMessage(HttpMethod.Post, "/scim/v2/Users")
        {
            Content = new StringContent(
                JsonSerializer.Serialize(new ScimUser { UserName = $"bulk_del_{suffix}", Active = true }),
                Encoding.UTF8, ScimConstants.MediaType)
        };
        createReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _f.ScimToken);
        var createRes = await _http.SendAsync(createReq);
        Assert.Equal(HttpStatusCode.Created, createRes.StatusCode);
        var createdJson = await ReadJson(createRes);
        var userId = createdJson.GetProperty("id").GetString();

        var bulk = new ScimBulkRequest
        {
            Operations =
            [
                new ScimBulkOperation { Method = "DELETE", Path = $"/Users/{userId}" }
            ]
        };
        var res = await _http.SendAsync(AuthedPost("/scim/v2/Bulk", bulk));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        var json = await ReadJson(res);
        var ops = json.GetProperty("Operations");
        Assert.Equal("204", ops[0].GetProperty("status").GetString());
    }

    // ── Reject paths for resources we don't expose ──

    [Fact]
    public async Task Bulk_RejectsUnsupportedPath()
    {
        var request = new ScimBulkRequest
        {
            Operations =
            [
                new ScimBulkOperation { Method = "POST", Path = "/Things", Data = AsJson(new { x = 1 }) }
            ]
        };
        var res = await _http.SendAsync(AuthedPost("/scim/v2/Bulk", request));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        var json = await ReadJson(res);
        Assert.Equal("400", json.GetProperty("Operations")[0].GetProperty("status").GetString());
    }
}
