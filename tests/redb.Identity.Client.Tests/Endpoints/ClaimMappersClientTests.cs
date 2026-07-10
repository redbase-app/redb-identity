using System.Net;
using FluentAssertions;
using redb.Identity.Client.Tests.TestKit;
using redb.Identity.Contracts.ClaimMappers;
using redb.Identity.Contracts.Common;
using Xunit;

namespace redb.Identity.Client.Tests.Endpoints;

public sealed class ClaimMappersClientTests
{
    // ── Mappers ──

    [Fact]
    public async Task ListClaimMappers_GETs_paged_no_owner()
    {
        var paged = new PagedResult<ClaimMapperResponse> { Items = [], Total = 0, Offset = 0, Count = 25 };
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(paged));
        await fx.Client.ListClaimMappersAsync();
        fx.Handler.Requests.Single().RequestUri!.PathAndQuery.Should().Be("/api/v1/identity/claim-mappers?offset=0&count=25");
    }

    [Fact]
    public async Task ListClaimMappers_GETs_paged_with_owner_filter()
    {
        var paged = new PagedResult<ClaimMapperResponse> { Items = [], Total = 0, Offset = 0, Count = 25 };
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(paged));
        await fx.Client.ListClaimMappersAsync(owner: "application:abc");
        fx.Handler.Requests.Single().RequestUri!.PathAndQuery
            .Should().Be("/api/v1/identity/claim-mappers?offset=0&count=25&owner=application%3Aabc");
    }

    [Fact]
    public async Task GetClaimMapper_GET_by_id()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(new ClaimMapperResponse { Id = "m1" }));
        await fx.Client.GetClaimMapperAsync("m1");
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/claim-mappers/m1");
    }

    [Fact]
    public async Task CreateClaimMapper_POST()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.Created, IdentityClientFixture.Json(new ClaimMapperResponse { Id = "m2" }));
        await fx.Client.CreateClaimMapperAsync(new CreateClaimMapperRequest { Name = "n", ClaimType = "ct", SourceKind = "Constant", ConstantValue = "v" });
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Post);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/claim-mappers");
    }

    [Fact]
    public async Task UpdateClaimMapper_PUT()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(new ClaimMapperResponse { Id = "m1" }));
        await fx.Client.UpdateClaimMapperAsync("m1", new UpdateClaimMapperRequest { Id = "m1" });
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Put);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/claim-mappers/m1");
    }

    [Fact]
    public async Task DeleteClaimMapper_DELETE()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.NoContent);
        await fx.Client.DeleteClaimMapperAsync("m1");
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Delete);
    }

    // ── Scopes ──

    [Fact]
    public async Task ListClaimScopes_GET()
    {
        var paged = new PagedResult<ClaimScopeResponse> { Items = [], Total = 0, Offset = 0, Count = 25 };
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(paged));
        await fx.Client.ListClaimScopesAsync();
        fx.Handler.Requests.Single().RequestUri!.PathAndQuery.Should().Be("/api/v1/identity/claim-scopes?offset=0&count=25");
    }

    [Fact]
    public async Task GetClaimScope_GET_by_id()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(new ClaimScopeResponse { Id = "cs1" }));
        await fx.Client.GetClaimScopeAsync("cs1");
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/claim-scopes/cs1");
    }

    [Fact]
    public async Task CreateClaimScope_POST()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.Created, IdentityClientFixture.Json(new ClaimScopeResponse { Id = "cs2" }));
        await fx.Client.CreateClaimScopeAsync(new CreateClaimScopeRequest { Name = "x" });
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Post);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/claim-scopes");
    }

    [Fact]
    public async Task UpdateClaimScope_PUT()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(new ClaimScopeResponse { Id = "cs1" }));
        await fx.Client.UpdateClaimScopeAsync("cs1", new UpdateClaimScopeRequest { Id = "cs1" });
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Put);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/claim-scopes/cs1");
    }

    [Fact]
    public async Task DeleteClaimScope_DELETE()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.NoContent);
        await fx.Client.DeleteClaimScopeAsync("cs1");
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Delete);
    }

    // ── Assignments ──

    [Fact]
    public async Task ListClaimScopeAssignments_GETs_query_string()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "[{\"id\":\"a1\",\"applicationId\":\"app\",\"scopeId\":\"cs1\"}]");
        var doc = await fx.Client.ListClaimScopeAssignmentsAsync("app");
        fx.Handler.Requests.Single().RequestUri!.PathAndQuery
            .Should().Be("/api/v1/identity/claim-scopes/assignments?applicationId=app");
        doc.GetArrayLength().Should().Be(1);
    }

    [Fact]
    public async Task AssignClaimScope_POST()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"id\":\"a1\",\"applicationId\":\"app\",\"scopeId\":\"cs1\"}");
        var doc = await fx.Client.AssignClaimScopeAsync(new AssignClaimScopeRequest { ApplicationId = "app", ScopeId = "cs1" });
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Post);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/claim-scopes/assignments");
        doc.GetProperty("id").GetString().Should().Be("a1");
    }

    [Fact]
    public async Task UnassignClaimScope_DELETE_with_query()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.NoContent);
        await fx.Client.UnassignClaimScopeAsync("app", "cs1");
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Delete);
        fx.Handler.Requests.Single().RequestUri!.PathAndQuery
            .Should().Be("/api/v1/identity/claim-scopes/assignments?applicationId=app&scopeId=cs1");
    }
}
