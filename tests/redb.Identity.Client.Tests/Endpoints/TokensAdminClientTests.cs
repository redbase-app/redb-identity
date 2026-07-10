using System.Net;
using FluentAssertions;
using redb.Identity.Client.Tests.TestKit;
using Xunit;

namespace redb.Identity.Client.Tests.Endpoints;

public sealed class TokensAdminClientTests
{
    [Fact]
    public async Task ListTokens_GET_no_subject()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"items\":[]}");
        await fx.Client.ListTokensAsync();
        fx.Handler.Requests.Single().RequestUri!.PathAndQuery.Should().Be("/api/v1/identity/tokens?offset=0&count=20");
    }

    [Fact]
    public async Task ListTokens_GET_with_subject_filter()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"items\":[]}");
        await fx.Client.ListTokensAsync(subject: "alice", offset: 5, count: 10);
        fx.Handler.Requests.Single().RequestUri!.PathAndQuery.Should().Be("/api/v1/identity/tokens?offset=5&count=10&subject=alice");
    }

    [Fact]
    public async Task RevokeToken_DELETE_by_id()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"success\":true}");
        await fx.Client.RevokeTokenAdminAsync("tk1");
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Delete);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/tokens/tk1");
    }

    [Fact]
    public async Task RevokeTokensBySubject_POST_with_body()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"revoked\":3}");
        await fx.Client.RevokeTokensBySubjectAsync(new Dictionary<string, object> { ["subject"] = "alice" });
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Post);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/tokens/revoke-by-subject");
        fx.Handler.RequestBodies[0].Should().Contain("\"subject\":\"alice\"");
    }

    [Fact]
    public async Task PruneTokens_POST_to_prune_subroute()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"pruned\":42}");
        await fx.Client.PruneTokensAsync();
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Post);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/tokens/prune");
    }
}
