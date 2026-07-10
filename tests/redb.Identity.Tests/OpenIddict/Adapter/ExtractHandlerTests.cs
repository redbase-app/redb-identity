using FluentAssertions;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using redb.Identity.Core.OpenIddict;
using redb.Identity.Core.OpenIddict.Handlers;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Tests.Adapter;

public class ExtractHandlerTests
{
    private static OpenIddictServerTransaction CreateTransaction(TestExchange exchange)
    {
        var transaction = new OpenIddictServerTransaction();
        transaction.Properties[RedbRouteOpenIddictServerHelpers.ExchangePropertyKey] = exchange;
        return transaction;
    }

    [Fact]
    public async Task ExtractToken_DictionaryStringString_PopulatesRequest()
    {
        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "my-app",
            ["client_secret"] = "my-secret",
            ["scope"] = "api"
        };

        var context = new ExtractTokenRequestContext(CreateTransaction(exchange));
        var handler = new ExtractTokenRequestHandler();
        await handler.HandleAsync(context);

        context.Request.Should().NotBeNull();
        context.Request!.GrantType.Should().Be(GrantTypes.ClientCredentials);
        context.Request.ClientId.Should().Be("my-app");
        context.Request.ClientSecret.Should().Be("my-secret");
        context.Request.Scope.Should().Be("api");
    }

    [Fact]
    public async Task ExtractToken_DictionaryStringObject_PopulatesRequest()
    {
        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, object?>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = "abc123",
            ["redirect_uri"] = "https://example.com/cb"
        };

        var context = new ExtractTokenRequestContext(CreateTransaction(exchange));
        await new ExtractTokenRequestHandler().HandleAsync(context);

        context.Request.Should().NotBeNull();
        context.Request!.GrantType.Should().Be(GrantTypes.AuthorizationCode);
        context.Request.Code.Should().Be("abc123");
        context.Request.RedirectUri.Should().Be("https://example.com/cb");
    }

    [Fact]
    public async Task ExtractToken_FormUrlEncodedString_PopulatesRequest()
    {
        var exchange = new TestExchange();
        exchange.In.Body = "grant_type=client_credentials&client_id=url-app&client_secret=s%26cret";

        var context = new ExtractTokenRequestContext(CreateTransaction(exchange));
        await new ExtractTokenRequestHandler().HandleAsync(context);

        context.Request.Should().NotBeNull();
        context.Request!.GrantType.Should().Be(GrantTypes.ClientCredentials);
        context.Request.ClientId.Should().Be("url-app");
        context.Request.ClientSecret.Should().Be("s&cret"); // decoded
    }

    [Fact]
    public async Task ExtractToken_OpenIddictRequest_UsedDirectly()
    {
        var original = new OpenIddictRequest
        {
            GrantType = GrantTypes.ClientCredentials,
            ClientId = "direct-client"
        };

        var exchange = new TestExchange();
        exchange.In.Body = original;

        var context = new ExtractTokenRequestContext(CreateTransaction(exchange));
        await new ExtractTokenRequestHandler().HandleAsync(context);

        context.Request.Should().BeSameAs(original);
    }

    [Fact]
    public async Task ExtractToken_NullBody_CreatesEmptyRequest()
    {
        var exchange = new TestExchange();
        exchange.In.Body = null;

        var context = new ExtractTokenRequestContext(CreateTransaction(exchange));
        await new ExtractTokenRequestHandler().HandleAsync(context);

        context.Request.Should().NotBeNull();
        context.Request!.GrantType.Should().BeNull();
    }

    [Fact]
    public async Task ExtractToken_NoExchangeInTransaction_Skips()
    {
        var transaction = new OpenIddictServerTransaction();
        // No exchange stored → handler should skip

        var context = new ExtractTokenRequestContext(transaction);
        await new ExtractTokenRequestHandler().HandleAsync(context);

        context.Request.Should().BeNull();
    }

    [Fact]
    public async Task ExtractAuthorization_PopulatesRequest()
    {
        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = "auth-client",
            ["redirect_uri"] = "https://example.com/cb",
            ["scope"] = "openid profile"
        };

        var context = new ExtractAuthorizationRequestContext(CreateTransaction(exchange));
        await new ExtractAuthorizationRequestHandler().HandleAsync(context);

        context.Request.Should().NotBeNull();
        context.Request!.ResponseType.Should().Be("code");
        context.Request.ClientId.Should().Be("auth-client");
    }

    [Fact]
    public async Task ExtractIntrospection_PopulatesRequest()
    {
        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["token"] = "my-token",
            ["token_type_hint"] = "access_token"
        };

        var context = new ExtractIntrospectionRequestContext(CreateTransaction(exchange));
        await new ExtractIntrospectionRequestHandler().HandleAsync(context);

        context.Request.Should().NotBeNull();
        context.Request!.Token.Should().Be("my-token");
        context.Request.TokenTypeHint.Should().Be("access_token");
    }

    [Fact]
    public async Task ExtractRevocation_PopulatesRequest()
    {
        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["token"] = "revoke-token"
        };

        var context = new ExtractRevocationRequestContext(CreateTransaction(exchange));
        await new ExtractRevocationRequestHandler().HandleAsync(context);

        context.Request.Should().NotBeNull();
        context.Request!.Token.Should().Be("revoke-token");
    }

    [Fact]
    public async Task ExtractUserinfo_BearerToken_SetsAccessToken()
    {
        var exchange = new TestExchange();
        exchange.In.Body = null;
        exchange.In.Headers["Authorization"] = "Bearer eyJhbGciOiJSUzI1NiJ9";

        var context = new ExtractUserInfoRequestContext(CreateTransaction(exchange));
        await new ExtractUserinfoRequestHandler().HandleAsync(context);

        context.Request.Should().NotBeNull();
        context.Request!.AccessToken.Should().Be("eyJhbGciOiJSUzI1NiJ9");
    }
}
