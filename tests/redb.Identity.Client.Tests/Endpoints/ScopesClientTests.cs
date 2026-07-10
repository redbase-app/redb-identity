using System.Net;
using FluentAssertions;
using redb.Identity.Client.Tests.TestKit;
using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Scopes;
using Xunit;

namespace redb.Identity.Client.Tests.Endpoints;

public sealed class ScopesClientTests
{
    [Fact]
    public async Task ListScopes_GET()
    {
        var paged = new PagedResult<ScopeResponse> { Items = [new() { Id = "s1", Name = "scope.read" }], Total = 1, Offset = 0, Count = 25 };
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(paged));
        var result = await fx.Client.ListScopesAsync();
        fx.Handler.Requests.Single().RequestUri!.PathAndQuery.Should().Be("/api/v1/identity/scopes?offset=0&count=25");
        result.Items[0].Name.Should().Be("scope.read");
    }

    [Fact]
    public async Task GetScope_GET_by_id()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(new ScopeResponse { Id = "s1", Name = "n" }));
        await fx.Client.GetScopeAsync("s1");
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/scopes/s1");
    }

    [Fact]
    public async Task CreateScope_POST()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.Created, IdentityClientFixture.Json(new ScopeResponse { Id = "s2" }));
        await fx.Client.CreateScopeAsync(new CreateScopeRequest { Name = "x" });
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Post);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/scopes");
    }

    [Fact]
    public async Task UpdateScope_PUT()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(new ScopeResponse { Id = "s1" }));
        await fx.Client.UpdateScopeAsync("s1", new UpdateScopeRequest { Id = "s1" });
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Put);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/scopes/s1");
    }

    [Fact]
    public async Task DeleteScope_DELETE()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.NoContent);
        await fx.Client.DeleteScopeAsync("s1");
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Delete);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/scopes/s1");
    }
}
