using System.Net;
using FluentAssertions;
using redb.Identity.Client.Tests.TestKit;
using redb.Identity.Contracts.Tokens;
using Xunit;

namespace redb.Identity.Client.Tests.Endpoints;

public sealed class TokenOAuthClientTests
{
    [Fact]
    public async Task RequestToken_POSTs_form_urlencoded_to_connect_token()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(new TokenResponse { AccessToken = "abc", TokenType = "Bearer", ExpiresIn = 3600 }));

        var resp = await fx.Client.RequestTokenAsync(new TokenRequest
        {
            GrantType = "client_credentials",
            ClientId = "cli",
            ClientSecret = "sec",
            Scope = "identity.admin",
        });

        var req = fx.Handler.Requests.Single();
        req.Method.Should().Be(HttpMethod.Post);
        req.RequestUri!.AbsolutePath.Should().Be("/connect/token");
        req.Content!.Headers.ContentType!.MediaType.Should().Be("application/x-www-form-urlencoded");
        var body = fx.Handler.RequestBodies[0]!;
        body.Should().Contain("grant_type=client_credentials")
            .And.Contain("client_id=cli")
            .And.Contain("client_secret=sec");
        // scope value may be URL-encoded
        (body.Contains("scope=identity.admin") || body.Contains("scope=identity%2Eadmin")).Should().BeTrue();
        resp.AccessToken.Should().Be("abc");
    }

    [Fact]
    public async Task IntrospectToken_POSTs_form_to_connect_introspect()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"active\":true}");

        await fx.Client.IntrospectTokenAsync(token: "tk", tokenTypeHint: "access_token", clientId: "cli", clientSecret: "sec");

        var req = fx.Handler.Requests.Single();
        req.RequestUri!.AbsolutePath.Should().Be("/connect/introspect");
        req.Content!.Headers.ContentType!.MediaType.Should().Be("application/x-www-form-urlencoded");
        fx.Handler.RequestBodies[0].Should().Contain("token=tk")
            .And.Contain("token_type_hint=access_token")
            .And.Contain("client_id=cli");
    }

    [Fact]
    public async Task RevokeOAuthToken_POSTs_form_to_connect_revocation()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{}");
        await fx.Client.RevokeOAuthTokenAsync("tk", tokenTypeHint: "refresh_token");
        var req = fx.Handler.Requests.Single();
        req.RequestUri!.AbsolutePath.Should().Be("/connect/revocation");
        fx.Handler.RequestBodies[0].Should().Contain("token=tk").And.Contain("token_type_hint=refresh_token");
    }

    [Fact]
    public async Task GetUserInfo_GET_to_connect_userinfo()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"sub\":\"alice\"}");
        var info = await fx.Client.GetUserInfoAsync();
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Get);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/connect/userinfo");
        info.GetProperty("sub").GetString().Should().Be("alice");
    }
}
