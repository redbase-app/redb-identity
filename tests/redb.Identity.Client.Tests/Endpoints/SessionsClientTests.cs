using System.Net;
using FluentAssertions;
using redb.Identity.Client.Tests.TestKit;
using Xunit;

namespace redb.Identity.Client.Tests.Endpoints;

public sealed class SessionsClientTests
{
    [Fact]
    public async Task ListSessions_GET_with_userId_query()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "[]");
        await fx.Client.ListSessionsAsync(42);
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Get);
        fx.Handler.Requests.Single().RequestUri!.PathAndQuery.Should().Be("/api/v1/identity/sessions?userId=42");
    }

    [Fact]
    public async Task RevokeSession_DELETE_with_sessionId_query()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"success\":true}");
        await fx.Client.RevokeSessionAsync(7);
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Delete);
        fx.Handler.Requests.Single().RequestUri!.PathAndQuery.Should().Be("/api/v1/identity/sessions?sessionId=7");
    }

    [Fact]
    public async Task RevokeAllUserSessions_DELETE_to_all_subroute()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"success\":true}");
        await fx.Client.RevokeAllUserSessionsAsync(42);
        fx.Handler.Requests.Single().RequestUri!.PathAndQuery.Should().Be("/api/v1/identity/sessions/all?userId=42");
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Delete);
    }

    [Fact]
    public async Task ForceLogoutUser_POST_to_logout_subroute()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"success\":true}");
        await fx.Client.ForceLogoutUserAsync(42);
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Post);
        fx.Handler.Requests.Single().RequestUri!.PathAndQuery.Should().Be("/api/v1/identity/sessions/logout?userId=42");
    }
}
