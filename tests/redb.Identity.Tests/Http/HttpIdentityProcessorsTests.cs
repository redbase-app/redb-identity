using FluentAssertions;
using NSubstitute;
using redb.Identity.Http.Processors;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.Http;
using Xunit;

namespace redb.Identity.Tests.Http;

public class HttpIdentityProcessorsTests
{
    // ── MapHttpToIdentityHeaders ──

    [Fact]
    public async Task MapHttpToIdentityHeaders_BasicAuth_SetsClientIdAndSecret()
    {
        var exchange = CreateExchange();
        var encoded = Convert.ToBase64String("my-client:my-secret"u8);
        exchange.In.Headers[HttpHeaders.Authorization] = $"Basic {encoded}";

        await HttpIdentityProcessors.MapHttpToIdentityHeaders(exchange, CancellationToken.None);

        exchange.In.GetHeader<string>("client_id").Should().Be("my-client");
        exchange.In.GetHeader<string>("client_secret").Should().Be("my-secret");
    }

    [Fact]
    public async Task MapHttpToIdentityHeaders_BasicAuth_NoSecret_SetsOnlyClientId()
    {
        var exchange = CreateExchange();
        var encoded = Convert.ToBase64String("client-only"u8);
        exchange.In.Headers[HttpHeaders.Authorization] = $"Basic {encoded}";

        await HttpIdentityProcessors.MapHttpToIdentityHeaders(exchange, CancellationToken.None);

        exchange.In.GetHeader<string>("client_id").Should().Be("client-only");
        exchange.In.Headers.ContainsKey("client_secret").Should().BeFalse();
    }

    [Fact]
    public async Task MapHttpToIdentityHeaders_UrlEncodedCredentials_Decoded()
    {
        var exchange = CreateExchange();
        var encoded = Convert.ToBase64String("client%3Aid:secret%26value"u8);
        exchange.In.Headers[HttpHeaders.Authorization] = $"Basic {encoded}";

        await HttpIdentityProcessors.MapHttpToIdentityHeaders(exchange, CancellationToken.None);

        exchange.In.GetHeader<string>("client_id").Should().Be("client:id");
        exchange.In.GetHeader<string>("client_secret").Should().Be("secret&value");
    }

    [Fact]
    public async Task MapHttpToIdentityHeaders_NoAuth_DoesNotThrow()
    {
        var exchange = CreateExchange();
        await HttpIdentityProcessors.MapHttpToIdentityHeaders(exchange, CancellationToken.None);

        exchange.In.Headers.ContainsKey("client_id").Should().BeFalse();
    }

    [Fact]
    public async Task MapHttpToIdentityHeaders_PropagatesContentType()
    {
        var exchange = CreateExchange();
        exchange.In.Headers[HttpHeaders.ContentType] = "application/x-www-form-urlencoded";

        await HttpIdentityProcessors.MapHttpToIdentityHeaders(exchange, CancellationToken.None);

        exchange.In.GetHeader<string>("Content-Type").Should().Be("application/x-www-form-urlencoded");
    }

    // ── ExtractBearerToken ──

    [Fact]
    public async Task ExtractBearerToken_ValidBearer_SetsAccessToken()
    {
        var exchange = CreateExchange();
        exchange.In.Headers[HttpHeaders.Authorization] = "Bearer eyJhbGciOiJSUzI1NiJ9.test";

        await HttpIdentityProcessors.ExtractBearerToken(exchange, CancellationToken.None);

        exchange.In.GetHeader<string>("access_token").Should().Be("eyJhbGciOiJSUzI1NiJ9.test");
    }

    [Fact]
    public async Task ExtractBearerToken_CaseInsensitive()
    {
        var exchange = CreateExchange();
        exchange.In.Headers[HttpHeaders.Authorization] = "bearer my-token";

        await HttpIdentityProcessors.ExtractBearerToken(exchange, CancellationToken.None);

        exchange.In.GetHeader<string>("access_token").Should().Be("my-token");
    }

    [Fact]
    public async Task ExtractBearerToken_NotBearer_Ignores()
    {
        var exchange = CreateExchange();
        exchange.In.Headers[HttpHeaders.Authorization] = "Basic abc";

        await HttpIdentityProcessors.ExtractBearerToken(exchange, CancellationToken.None);

        exchange.In.Headers.ContainsKey("access_token").Should().BeFalse();
    }

    // ── MapQueryToBody ──

    [Fact]
    public async Task MapQueryToBody_ParsesQueryString()
    {
        var exchange = CreateExchange();
        exchange.In.Headers[HttpHeaders.Query] = "client_id=app&response_type=code&scope=openid+profile";

        await HttpIdentityProcessors.MapQueryToBody(exchange, CancellationToken.None);

        var body = exchange.In.Body as IDictionary<string, object?>;
        body.Should().NotBeNull();
        body!["client_id"].Should().Be("app");
        body["response_type"].Should().Be("code");
        body["scope"].Should().Be("openid profile");
    }

    [Fact]
    public async Task MapQueryToBody_EmptyQuery_NoChange()
    {
        var exchange = CreateExchange();
        exchange.In.Body = "original";

        await HttpIdentityProcessors.MapQueryToBody(exchange, CancellationToken.None);

        exchange.In.Body.Should().Be("original");
    }

    // ── MapFormToBody ──

    [Fact]
    public async Task MapFormToBody_ParsesFormBody()
    {
        var exchange = CreateExchange();
        exchange.In.Body = "grant_type=client_credentials&client_id=app";

        await HttpIdentityProcessors.MapFormToBody(exchange, CancellationToken.None);

        var body = exchange.In.Body as IDictionary<string, object?>;
        body.Should().NotBeNull();
        body!["grant_type"].Should().Be("client_credentials");
        body["client_id"].Should().Be("app");
    }

    // ── HandleRedirectResponse ──

    [Fact]
    public async Task HandleRedirectResponse_SetsRedirectHeaders()
    {
        var exchange = CreateExchange();
        exchange.Out = new Message();
        exchange.Out.Headers["redirect_uri"] = "https://app.test/callback?code=abc&state=xyz";

        await HttpIdentityProcessors.HandleRedirectResponse(exchange, CancellationToken.None);

        exchange.Out.GetHeader<int>(HttpHeaders.ResponseCode).Should().Be(302);
        exchange.Out.GetHeader<string>("Location")
            .Should().Be("https://app.test/callback?code=abc&state=xyz");
    }

    [Fact]
    public async Task HandleRedirectResponse_NoRedirect_NoChange()
    {
        var exchange = CreateExchange();
        exchange.Out = new Message();
        exchange.Out.Body = "normal response";

        await HttpIdentityProcessors.HandleRedirectResponse(exchange, CancellationToken.None);

        exchange.Out.Headers.ContainsKey("Location").Should().BeFalse();
    }

    // ── StripManagementPrefix ──

    [Fact]
    public async Task StripManagementPrefix_RemovesApiIdentityPrefix()
    {
        var exchange = CreateExchange();
        exchange.In.Headers[HttpHeaders.Path] = "/api/v1/identity/applications/123";

        await HttpIdentityProcessors.StripManagementPrefix(exchange, CancellationToken.None);

        exchange.In.GetHeader<string>(HttpHeaders.Path).Should().Be("/applications/123");
    }

    [Fact]
    public async Task StripManagementPrefix_RootPath_BecomesSingleSlash()
    {
        var exchange = CreateExchange();
        exchange.In.Headers[HttpHeaders.Path] = "/api/v1/identity/";

        await HttpIdentityProcessors.StripManagementPrefix(exchange, CancellationToken.None);

        exchange.In.GetHeader<string>(HttpHeaders.Path).Should().Be("/");
    }

    [Fact]
    public async Task StripManagementPrefix_NoPrefix_Unchanged()
    {
        var exchange = CreateExchange();
        exchange.In.Headers[HttpHeaders.Path] = "/connect/token";

        await HttpIdentityProcessors.StripManagementPrefix(exchange, CancellationToken.None);

        exchange.In.GetHeader<string>(HttpHeaders.Path).Should().Be("/connect/token");
    }

    // ── Helper ──

    private static IExchange CreateExchange() => new Exchange(new Message());
}
