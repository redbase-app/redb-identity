using System.Net;
using FluentAssertions;
using redb.Identity.Client.Tests.TestKit;
using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Federation;
using Xunit;

namespace redb.Identity.Client.Tests.Endpoints;

public sealed class FederationClientTests
{
    [Fact]
    public async Task ListFederationProviders_GET()
    {
        var paged = new PagedResult<FederationProviderResponse>
        {
            Items = [new() { Id = "p1", ProviderId = "google", Kind = "oidc", DisplayName = "Google", ClientId = "g", Scopes = ["openid"] }],
            Total = 1, Offset = 0, Count = 25,
        };
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(paged));
        var result = await fx.Client.ListFederationProvidersAsync();
        fx.Handler.Requests.Single().RequestUri!.PathAndQuery.Should().Be("/api/v1/identity/federation-providers?offset=0&count=25");
        result.Items[0].ProviderId.Should().Be("google");
    }

    [Fact]
    public async Task GetFederationProvider_GET_by_id()
    {
        var fp = new FederationProviderResponse { Id = "p1", ProviderId = "x", Kind = "oidc", DisplayName = "X", ClientId = "c", Scopes = [] };
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(fp));
        await fx.Client.GetFederationProviderAsync("p1");
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/federation-providers/p1");
    }

    [Fact]
    public async Task CreateFederationProvider_POST()
    {
        var fp = new FederationProviderResponse { Id = "p2", ProviderId = "github", Kind = "github", DisplayName = "GH", ClientId = "x", Scopes = [] };
        var fx = new IdentityClientFixture(HttpStatusCode.Created, IdentityClientFixture.Json(fp));
        var req = new CreateFederationProviderRequest { ProviderId = "github", Kind = "github", DisplayName = "GH", ClientId = "x" };
        await fx.Client.CreateFederationProviderAsync(req);
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Post);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/federation-providers");
    }

    [Fact]
    public async Task UpdateFederationProvider_PUT_writeonly_secret()
    {
        var fp = new FederationProviderResponse { Id = "p1", ProviderId = "x", Kind = "oidc", DisplayName = "X", ClientId = "c", Scopes = [], HasSecret = true };
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(fp));
        await fx.Client.UpdateFederationProviderAsync("p1", new UpdateFederationProviderRequest { Id = "p1", ClientSecret = "rotated" });
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Put);
        fx.Handler.RequestBodies[0].Should().Contain("\"clientSecret\":\"rotated\"");
    }

    [Fact]
    public async Task DeleteFederationProvider_DELETE()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.NoContent);
        await fx.Client.DeleteFederationProviderAsync("p1");
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Delete);
    }
}
