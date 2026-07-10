using System.Net;
using FluentAssertions;
using redb.Identity.Client.Tests.TestKit;
using redb.Identity.Contracts.Scim;
using Xunit;

namespace redb.Identity.Client.Tests.Endpoints;

public sealed class ScimClientTests
{
    private const string Base = "/scim/v2";

    // ── Discovery ──

    [Fact]
    public async Task GetServiceProviderConfig_GET()
    {
        var cfg = new ScimServiceProviderConfig { Bulk = new ScimBulkConfig { Supported = true, MaxOperations = 100 } };
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(cfg));
        var result = await fx.Client.GetScimServiceProviderConfigAsync();
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/ServiceProviderConfig");
        result.Bulk!.Supported.Should().BeTrue();
    }

    [Fact]
    public async Task GetResourceTypes_GET()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"Resources\":[]}");
        await fx.Client.GetScimResourceTypesAsync();
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/ResourceTypes");
    }

    [Fact]
    public async Task GetSchemas_GET()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"Resources\":[]}");
        await fx.Client.GetScimSchemasAsync();
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/Schemas");
    }

    // ── Users ──

    [Fact]
    public async Task ListScimUsers_GET_with_startIndex_count_filter()
    {
        var list = new ScimListResponse<ScimUser> { TotalResults = 0, ItemsPerPage = 25, StartIndex = 1, Resources = [] };
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(list));
        await fx.Client.ListScimUsersAsync(startIndex: 1, count: 25, filter: "userName eq \"alice\"");
        var qs = fx.Handler.Requests.Single().RequestUri!.PathAndQuery;
        qs.Should().StartWith($"{Base}/Users?")
          .And.Contain("startIndex=1")
          .And.Contain("count=25")
          .And.Contain("filter=userName%20eq%20%22alice%22");
    }

    [Fact]
    public async Task GetScimUser_GET_by_id()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(new ScimUser { Id = "u1", UserName = "alice" }));
        await fx.Client.GetScimUserAsync("u1");
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/Users/u1");
    }

    [Fact]
    public async Task CreateScimUser_POST()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.Created, IdentityClientFixture.Json(new ScimUser { Id = "u2", UserName = "bob" }));
        await fx.Client.CreateScimUserAsync(new ScimUser { UserName = "bob" });
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Post);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/Users");
    }

    [Fact]
    public async Task ReplaceScimUser_PUT_by_id()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(new ScimUser { Id = "u1", UserName = "alice2" }));
        await fx.Client.ReplaceScimUserAsync("u1", new ScimUser { Id = "u1", UserName = "alice2" });
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Put);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/Users/u1");
    }

    [Fact]
    public async Task PatchScimUser_PATCH_by_id_with_ops()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(new ScimUser { Id = "u1" }));
        var patch = new ScimPatchRequest
        {
            Operations = [new ScimPatchOperation { Op = "replace", Path = "userName", Value = System.Text.Json.JsonDocument.Parse("\"renamed\"").RootElement }],
        };
        await fx.Client.PatchScimUserAsync("u1", patch);
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Patch);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/Users/u1");
    }

    [Fact]
    public async Task DeleteScimUser_DELETE_by_id()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.NoContent);
        await fx.Client.DeleteScimUserAsync("u1");
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Delete);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/Users/u1");
    }

    // ── Groups ──

    [Fact]
    public async Task ListScimGroups_GET_with_startIndex_count()
    {
        var list = new ScimListResponse<ScimGroup> { TotalResults = 0, ItemsPerPage = 25, StartIndex = 1, Resources = [] };
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(list));
        await fx.Client.ListScimGroupsAsync();
        var qs = fx.Handler.Requests.Single().RequestUri!.PathAndQuery;
        qs.Should().StartWith($"{Base}/Groups?").And.Contain("startIndex=1").And.Contain("count=25");
    }

    [Fact]
    public async Task GetScimGroup_GET_by_id()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(new ScimGroup { Id = "g1", DisplayName = "g" }));
        await fx.Client.GetScimGroupAsync("g1");
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/Groups/g1");
    }

    [Fact]
    public async Task CreateScimGroup_POST()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.Created, IdentityClientFixture.Json(new ScimGroup { Id = "g2", DisplayName = "g" }));
        await fx.Client.CreateScimGroupAsync(new ScimGroup { DisplayName = "g" });
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Post);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/Groups");
    }

    [Fact]
    public async Task ReplaceScimGroup_PUT_by_id()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(new ScimGroup { Id = "g1", DisplayName = "renamed" }));
        await fx.Client.ReplaceScimGroupAsync("g1", new ScimGroup { Id = "g1", DisplayName = "renamed" });
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Put);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/Groups/g1");
    }

    [Fact]
    public async Task PatchScimGroup_PATCH_by_id()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(new ScimGroup { Id = "g1" }));
        var patch = new ScimPatchRequest { Operations = [new ScimPatchOperation { Op = "add", Path = "members", Value = System.Text.Json.JsonDocument.Parse("\"u1\"").RootElement }] };
        await fx.Client.PatchScimGroupAsync("g1", patch);
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Patch);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/Groups/g1");
    }

    [Fact]
    public async Task DeleteScimGroup_DELETE_by_id()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.NoContent);
        await fx.Client.DeleteScimGroupAsync("g1");
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Delete);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/Groups/g1");
    }

    // ── Bulk ──

    [Fact]
    public async Task ExecuteScimBulk_POSTs_to_Bulk()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(new ScimBulkResponse { Operations = [] }));
        var req = new ScimBulkRequest { Operations = [new ScimBulkOperation { Method = "POST", Path = "/Users", BulkId = "1" }] };
        await fx.Client.ExecuteScimBulkAsync(req);
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Post);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be($"{Base}/Bulk");
    }
}
