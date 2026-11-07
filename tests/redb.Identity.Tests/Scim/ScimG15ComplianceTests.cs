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
/// G15 — regression guards for SCIM gaps that were listed under G15/PARTIAL:
/// <list type="bullet">
///   <item>PATCH <c>add</c>/<c>remove</c> ops (the existing suite only covered <c>replace</c>).</item>
///   <item><c>GET /scim/v2/Schemas</c> — required by RFC 7644 §4 discovery.</item>
///   <item><c>meta.version</c> weak-ETag field in the JSON body (RFC 7644 §3.14 + §3.1).</item>
///   <item>Pagination boundaries: <c>startIndex</c>/<c>count</c> reflected back in the list envelope.</item>
/// </list>
/// </summary>
[Collection("ProductionHttp")]
public class ScimG15ComplianceTests
{
    private readonly ProductionHttpFixture _f;
    private readonly HttpClient _http;
    private readonly ITestOutputHelper _out;

    public ScimG15ComplianceTests(ProductionHttpFixture fixture, ITestOutputHelper output)
    {
        _f = fixture;
        _http = fixture.Http;
        _out = output;
    }

    private HttpRequestMessage Scim(HttpMethod method, string path, object? body = null)
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

    private async Task<JsonElement> ReadJson(HttpResponseMessage r)
    {
        var raw = await r.Content.ReadAsStringAsync();
        _out.WriteLine($"[{(int)r.StatusCode}] {raw}");
        return JsonSerializer.Deserialize<JsonElement>(raw);
    }

    // ── /Schemas discovery ──────────────────────────────────────

    [Fact]
    public async Task Schemas_ReturnsUserAndGroupDefinitions()
    {
        var res = await _http.SendAsync(Scim(HttpMethod.Get, "/scim/v2/Schemas"));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var json = await ReadJson(res);
        // RFC 7644 §4 — Schemas resource returns a ListResponse of Schema definitions.
        Assert.True(json.TryGetProperty("Resources", out var resources),
            "/Schemas must return a SCIM ListResponse envelope with a Resources array");

        var ids = new List<string>();
        foreach (var schema in resources.EnumerateArray())
            if (schema.TryGetProperty("id", out var idProp) && idProp.GetString() is { } id)
                ids.Add(id);

        Assert.Contains("urn:ietf:params:scim:schemas:core:2.0:User", ids);
        Assert.Contains("urn:ietf:params:scim:schemas:core:2.0:Group", ids);
    }

    // ── meta.version weak-ETag in JSON body ─────────────────────

    [Fact]
    public async Task GetUser_IncludesWeakETagInMetaVersion()
    {
        // Seed a user so we have a deterministic id to read back.
        var userName = $"g15-meta-{Guid.NewGuid():N}";
        var createRes = await _http.SendAsync(Scim(HttpMethod.Post, "/scim/v2/Users",
            new ScimUser { UserName = userName, DisplayName = "G15 Meta" }));
        Assert.Equal(HttpStatusCode.Created, createRes.StatusCode);
        var created = await ReadJson(createRes);
        var id = created.GetProperty("id").GetString();

        var readRes = await _http.SendAsync(Scim(HttpMethod.Get, $"/scim/v2/Users/{id}"));
        Assert.Equal(HttpStatusCode.OK, readRes.StatusCode);

        var body = await ReadJson(readRes);
        // Per RFC 7644 §3.14 the server SHOULD expose the resource version both as an HTTP
        // ETag header AND inside `meta.version`; the core RFC 7643 §3.1 reserves the field
        // for optimistic-concurrency clients that cannot read response headers easily.
        Assert.True(body.TryGetProperty("meta", out var meta), "meta object must be present on GET");
        Assert.True(meta.TryGetProperty("version", out var version), "meta.version must be present on GET");
        var versionStr = version.GetString();
        Assert.False(string.IsNullOrWhiteSpace(versionStr));
        Assert.StartsWith("W/\"", versionStr); // weak ETag shape

        // The HTTP ETag header must match meta.version exactly (same weak-tag representation).
        var etag = readRes.Headers.ETag?.ToString();
        Assert.Equal(versionStr, etag);
    }

    // ── PATCH add ───────────────────────────────────────────────

    [Fact]
    public async Task PatchUser_AddOp_SetsExternalId()
    {
        var tag = Guid.NewGuid().ToString("N");
        var userName = $"g15-patch-add-{tag}";

        var createRes = await _http.SendAsync(Scim(HttpMethod.Post, "/scim/v2/Users",
            new ScimUser { UserName = userName, DisplayName = "Before Add" }));
        Assert.Equal(HttpStatusCode.Created, createRes.StatusCode);
        var created = await ReadJson(createRes);
        var id = created.GetProperty("id").GetString();

        // RFC 7644 §3.5.2.1 — `add` op on a single-valued attribute MUST set / replace it.
        var patch = new ScimPatchRequest
        {
            Operations =
            [
                new ScimPatchOperation
                {
                    Op = "add",
                    Path = "externalId",
                    Value = JsonSerializer.SerializeToElement($"ext-{tag}")
                }
            ]
        };

        var res = await _http.SendAsync(Scim(HttpMethod.Patch, $"/scim/v2/Users/{id}", patch));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var body = await ReadJson(res);
        Assert.Equal($"ext-{tag}", body.GetProperty("externalId").GetString());
    }

    // ── PATCH remove ────────────────────────────────────────────

    [Fact]
    public async Task PatchUser_RemoveOp_ClearsGivenName()
    {
        var tag = Guid.NewGuid().ToString("N");
        var userName = $"g15-patch-remove-{tag}";

        var createRes = await _http.SendAsync(Scim(HttpMethod.Post, "/scim/v2/Users",
            new ScimUser
            {
                UserName = userName,
                DisplayName = "Before Remove",
                Name = new ScimName { GivenName = "ToRemove", FamilyName = "Keep" }
            }));
        Assert.Equal(HttpStatusCode.Created, createRes.StatusCode);
        var created = await ReadJson(createRes);
        var id = created.GetProperty("id").GetString();

        // Sanity — givenName must be present before the remove op.
        Assert.Equal("ToRemove",
            created.GetProperty("name").GetProperty("givenName").GetString());

        // RFC 7644 §3.5.2.2 — `remove` clears the attribute; subsequent GET must not include it
        // (or return null for single-valued attributes).
        var patch = new ScimPatchRequest
        {
            Operations =
            [
                new ScimPatchOperation { Op = "remove", Path = "name.givenName" }
            ]
        };

        var res = await _http.SendAsync(Scim(HttpMethod.Patch, $"/scim/v2/Users/{id}", patch));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var body = await ReadJson(res);
        // After remove: either `name.givenName` is absent, or null. Either interpretation is
        // RFC-compliant for a single-valued attribute (§3.5.2.2). familyName must remain.
        if (body.TryGetProperty("name", out var name))
        {
            if (name.TryGetProperty("givenName", out var given))
                Assert.True(given.ValueKind == JsonValueKind.Null || string.IsNullOrEmpty(given.GetString()),
                    "givenName must be cleared after `remove` op");
            Assert.Equal("Keep", name.GetProperty("familyName").GetString());
        }
    }

    // ── Pagination boundaries ───────────────────────────────────

    [Fact]
    public async Task ListUsers_PaginationEnvelope_EchoesStartIndexAndItemsPerPage()
    {
        // Create at least 3 users so we can page non-trivially.
        var prefix = $"g15-page-{Guid.NewGuid():N}-";
        for (int i = 0; i < 3; i++)
            await _http.SendAsync(Scim(HttpMethod.Post, "/scim/v2/Users",
                new ScimUser { UserName = $"{prefix}{i}" }));

        var res = await _http.SendAsync(Scim(HttpMethod.Get,
            "/scim/v2/Users?startIndex=1&count=2"));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var json = await ReadJson(res);
        // RFC 7644 §3.4.2.4 — the response envelope MUST include totalResults + startIndex
        // + itemsPerPage; startIndex MUST match the request (server can cap `count` but MUST
        // document it via ServiceProviderConfig; we already verify the 100 cap elsewhere).
        Assert.Equal(1, json.GetProperty("startIndex").GetInt32());
        var itemsPerPage = json.GetProperty("itemsPerPage").GetInt32();
        Assert.True(itemsPerPage <= 2, "itemsPerPage must not exceed requested count");

        // Page 2 must start at index 3 (given startIndex=3 in request).
        var res2 = await _http.SendAsync(Scim(HttpMethod.Get,
            "/scim/v2/Users?startIndex=3&count=2"));
        Assert.Equal(HttpStatusCode.OK, res2.StatusCode);
        var json2 = await ReadJson(res2);
        Assert.Equal(3, json2.GetProperty("startIndex").GetInt32());
    }
}
