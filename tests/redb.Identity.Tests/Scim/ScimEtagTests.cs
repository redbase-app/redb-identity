using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Contracts.Scim;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.Scim;

/// <summary>
/// G15 — SCIM 2.0 ETag / If-Match precondition compliance (RFC 7644 §3.14).
/// <list type="bullet">
///   <item>Every successful resource response must carry a strong-ish <c>ETag</c>
///         header (we expose <c>core_users.Hash</c> as the version token).</item>
///   <item><c>If-Match: "&lt;current-etag&gt;"</c> on PUT/PATCH succeeds.</item>
///   <item><c>If-Match: "&lt;stale-etag&gt;"</c> on PUT/PATCH returns
///         <c>412 Precondition Failed</c> — preventing lost updates from concurrent
///         provisioning agents (Azure Entra, Okta, …).</item>
/// </list>
/// </summary>
[Collection("ProductionHttp")]
public sealed class ScimEtagTests
{
    private readonly ProductionHttpFixture _fx;
    private readonly ITestOutputHelper _out;

    public ScimEtagTests(ProductionHttpFixture fx, ITestOutputHelper output)
    {
        _fx = fx;
        _out = output;
    }

    [Fact]
    public async Task GetUser_EmitsEtagHeader()
    {
        var (id, _) = await CreateUserAsync();

        using var req = ScimRequest(HttpMethod.Get, $"/scim/v2/Users/{id}");
        var resp = await _fx.Http.SendAsync(req);

        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        resp.Headers.ETag.Should().NotBeNull(
            "RFC 7644 §3.14 requires SCIM resource responses to carry an ETag header " +
            "so clients can perform conditional updates and avoid lost-update races.");
        resp.Headers.ETag!.Tag.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task PatchUser_WithCurrentEtag_Succeeds()
    {
        var (id, currentEtag) = await CreateUserAsync();

        var patch = new
        {
            schemas = new[] { "urn:ietf:params:scim:api:messages:2.0:PatchOp" },
            Operations = new object[]
            {
                new { op = "replace", path = "displayName", value = "Updated Name " + Guid.NewGuid().ToString("N")[..6] }
            }
        };

        using var req = ScimRequest(HttpMethod.Patch, $"/scim/v2/Users/{id}");
        req.Content = new StringContent(JsonSerializer.Serialize(patch), Encoding.UTF8, "application/scim+json");
        req.Headers.IfMatch.ParseAdd(currentEtag);

        var resp = await _fx.Http.SendAsync(req);

        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            "If-Match with the current ETag must succeed; got {0}: {1}",
            resp.StatusCode, await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task PatchUser_WithStaleEtag_Returns412()
    {
        var (id, originalEtag) = await CreateUserAsync();

        // First PATCH bumps the version (so originalEtag is now stale).
        // displayName must be unique per call — `_users._name` carries a UNIQUE constraint
        // and reusing a literal here would mask the real ETag-stale assertion below.
        var firstName = $"First Update {Guid.NewGuid():N}";
        var firstPatch = new
        {
            schemas = new[] { "urn:ietf:params:scim:api:messages:2.0:PatchOp" },
            Operations = new object[]
            {
                new { op = "replace", path = "displayName", value = firstName }
            }
        };
        using (var firstReq = ScimRequest(HttpMethod.Patch, $"/scim/v2/Users/{id}"))
        {
            firstReq.Content = new StringContent(
                JsonSerializer.Serialize(firstPatch), Encoding.UTF8, "application/scim+json");
            firstReq.Headers.IfMatch.ParseAdd(originalEtag);
            var firstResp = await _fx.Http.SendAsync(firstReq);
            var firstBody = await firstResp.Content.ReadAsStringAsync();
            _out.WriteLine($"[FIRST PATCH {(int)firstResp.StatusCode}] etag={firstResp.Headers.ETag?.Tag} body={firstBody}");

            firstResp.StatusCode.Should().Be(HttpStatusCode.OK,
                "first PATCH must succeed so the resource version (ETag) advances. Body: {0}", firstBody);
            firstBody.Should().NotContain("\"error\"",
                "PATCH response must not carry an OAuth-style error envelope when the HTTP status is 200. Body: {0}", firstBody);
            firstResp.Headers.ETag.Should().NotBeNull(
                "successful PATCH must echo the new resource ETag (RFC 7644 §3.14)");
            firstResp.Headers.ETag!.Tag.Should().NotBe(originalEtag,
                "first PATCH must advance the resource version — without this, optimistic concurrency cannot work.");
        }

        // Second PATCH using the now-stale originalEtag must be rejected with 412.
        var secondPatch = new
        {
            schemas = new[] { "urn:ietf:params:scim:api:messages:2.0:PatchOp" },
            Operations = new object[]
            {
                new { op = "replace", path = "displayName", value = $"Stale Update {Guid.NewGuid():N}" }
            }
        };
        using var staleReq = ScimRequest(HttpMethod.Patch, $"/scim/v2/Users/{id}");
        staleReq.Content = new StringContent(
            JsonSerializer.Serialize(secondPatch), Encoding.UTF8, "application/scim+json");
        staleReq.Headers.IfMatch.ParseAdd(originalEtag);

        var staleResp = await _fx.Http.SendAsync(staleReq);

        staleResp.StatusCode.Should().Be(HttpStatusCode.PreconditionFailed,
            "stale If-Match must return 412 (RFC 7644 §3.14 + RFC 7232 §4.2) — " +
            "without this guard concurrent provisioning agents would silently overwrite " +
            "each other's updates (lost-update on `displayName`, `emails`, etc.). " +
            "Server response: {0}", await staleResp.Content.ReadAsStringAsync());
    }

    // ─────────────── helpers ───────────────

    private HttpRequestMessage ScimRequest(HttpMethod method, string path)
    {
        var req = new HttpRequestMessage(method, path);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fx.ScimToken);
        req.Headers.Accept.ParseAdd("application/scim+json");
        return req;
    }

    private async Task<(string id, string etag)> CreateUserAsync()
    {
        var tag = Guid.NewGuid().ToString("N");
        var user = new ScimUser
        {
            UserName = $"scim-etag-{tag}",
            DisplayName = $"SCIM ETag {tag}"
        };

        var json = JsonSerializer.Serialize(user);
        _out.WriteLine($"[POST] payload={json}");

        using var req = ScimRequest(HttpMethod.Post, "/scim/v2/Users");
        req.Content = new StringContent(json, Encoding.UTF8, ScimConstants.MediaType);
        var resp = await _fx.Http.SendAsync(req);

        var body = await resp.Content.ReadAsStringAsync();
        _out.WriteLine($"[RESP {(int)resp.StatusCode}] {body}");
        resp.StatusCode.Should().Be(HttpStatusCode.Created,
            "SCIM POST /Users must succeed with a unique userName. Server: {0}", body);

        var responseJson = JsonDocument.Parse(body).RootElement;
        var id = responseJson.GetProperty("id").GetString()!;

        // POST response should carry the ETag too — fall back to a follow-up GET if not.
        string? etag = resp.Headers.ETag?.Tag;
        if (string.IsNullOrEmpty(etag))
        {
            using var getReq = ScimRequest(HttpMethod.Get, $"/scim/v2/Users/{id}");
            var getResp = await _fx.Http.SendAsync(getReq);
            etag = getResp.Headers.ETag?.Tag;
        }

        etag.Should().NotBeNullOrEmpty("the freshly created resource must expose an ETag");
        return (id, etag!);
    }
}
