using System.Net;
using FluentAssertions;
using redb.Identity.Client.Tests.TestKit;
using Xunit;

namespace redb.Identity.Client.Tests.Endpoints;

public sealed class ConsentsAdminClientTests
{
    [Fact]
    public async Task ListUserConsents_GET()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "[]");
        await fx.Client.ListUserConsentsAsync(42);
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Get);
        fx.Handler.Requests.Single().RequestUri!.PathAndQuery.Should().Be("/api/v1/identity/consents?userId=42");
    }

    [Fact]
    public async Task RevokeUserConsent_DELETE_with_userId_and_applicationId()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"success\":true}");
        await fx.Client.RevokeUserConsentAsync(42, 7);
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Delete);
        fx.Handler.Requests.Single().RequestUri!.PathAndQuery.Should().Be("/api/v1/identity/consents?userId=42&applicationId=7");
    }

    [Fact]
    public async Task RevokeAllUserConsents_DELETE_to_all_subroute()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"success\":true}");
        await fx.Client.RevokeAllUserConsentsAsync(42);
        fx.Handler.Requests.Single().RequestUri!.PathAndQuery.Should().Be("/api/v1/identity/consents/all?userId=42");
    }
}
