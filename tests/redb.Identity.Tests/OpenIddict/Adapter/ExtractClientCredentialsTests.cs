using FluentAssertions;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using redb.Identity.Core.OpenIddict;
using redb.Identity.Core.OpenIddict.Handlers;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Tests.Adapter;

public class ExtractClientCredentialsTests
{
    private static (ExtractTokenRequestContext context, TestExchange exchange) SetupToken(
        Dictionary<string, string>? body = null,
        string? authorizationHeader = null)
    {
        var exchange = new TestExchange();
        if (body != null) exchange.In.Body = body;
        if (authorizationHeader != null)
            exchange.In.Headers["Authorization"] = authorizationHeader;

        var transaction = new OpenIddictServerTransaction();
        transaction.Properties[RedbRouteOpenIddictServerHelpers.ExchangePropertyKey] = exchange;

        var context = new ExtractTokenRequestContext(transaction);

        // Pre-populate request (as if ExtractTokenRequestHandler already ran)
        context.Request = RedbRouteOpenIddictServerHelpers.CreateRequestFromExchange(exchange);
        return (context, exchange);
    }

    [Fact]
    public async Task BasicAuth_ExtractsClientIdAndSecret()
    {
        var credentials = Convert.ToBase64String(
            System.Text.Encoding.UTF8.GetBytes("my-client:my-secret"));

        var (context, _) = SetupToken(authorizationHeader: $"Basic {credentials}");
        await new ExtractClientCredentialsHandler().HandleAsync(context);

        context.Request!.ClientId.Should().Be("my-client");
        context.Request.ClientSecret.Should().Be("my-secret");
    }

    [Fact]
    public async Task BasicAuth_UrlEncodedCredentials_DecodesCorrectly()
    {
        // client_id contains special chars: "app%23test" → decoded "app#test"
        var credentials = Convert.ToBase64String(
            System.Text.Encoding.UTF8.GetBytes("app%23test:s%26cret"));

        var (context, _) = SetupToken(authorizationHeader: $"Basic {credentials}");
        await new ExtractClientCredentialsHandler().HandleAsync(context);

        context.Request!.ClientId.Should().Be("app#test");
        context.Request.ClientSecret.Should().Be("s&cret");
    }

    [Fact]
    public async Task BasicAuth_OverridesBodyCredentials()
    {
        var body = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "body-client",
            ["client_secret"] = "body-secret"
        };

        var credentials = Convert.ToBase64String(
            System.Text.Encoding.UTF8.GetBytes("header-client:header-secret"));

        var (context, _) = SetupToken(body, $"Basic {credentials}");
        await new ExtractClientCredentialsHandler().HandleAsync(context);

        // Basic auth should override body-based credentials (RFC 6749 §2.3.1)
        context.Request!.ClientId.Should().Be("header-client");
        context.Request.ClientSecret.Should().Be("header-secret");
    }

    [Fact]
    public async Task NoAuthorizationHeader_LeavesRequestUnchanged()
    {
        var body = new Dictionary<string, string>
        {
            ["client_id"] = "body-only",
            ["client_secret"] = "body-secret"
        };

        var (context, _) = SetupToken(body);
        await new ExtractClientCredentialsHandler().HandleAsync(context);

        context.Request!.ClientId.Should().Be("body-only");
        context.Request.ClientSecret.Should().Be("body-secret");
    }

    [Fact]
    public async Task BearerToken_NotBasic_LeavesRequestUnchanged()
    {
        var (context, _) = SetupToken(authorizationHeader: "Bearer eyJhbGciOiJSUzI1NiJ9");
        await new ExtractClientCredentialsHandler().HandleAsync(context);

        // Bearer tokens are not client credentials
        context.Request!.ClientId.Should().BeNull();
        context.Request.ClientSecret.Should().BeNull();
    }

    [Fact]
    public async Task InvalidBase64_DoesNotThrow()
    {
        var (context, _) = SetupToken(authorizationHeader: "Basic !!!not-base64!!!");
        await new ExtractClientCredentialsHandler().HandleAsync(context);

        // Should silently ignore invalid Base64
        context.Request!.ClientId.Should().BeNull();
    }

    [Fact]
    public async Task BasicAuth_NoColon_DoesNotSetCredentials()
    {
        var credentials = Convert.ToBase64String(
            System.Text.Encoding.UTF8.GetBytes("no-colon-here"));

        var (context, _) = SetupToken(authorizationHeader: $"Basic {credentials}");
        await new ExtractClientCredentialsHandler().HandleAsync(context);

        context.Request!.ClientId.Should().BeNull();
    }

    [Fact]
    public async Task NoExchangeInTransaction_Skips()
    {
        var transaction = new OpenIddictServerTransaction();
        transaction.Request = new OpenIddictRequest { ClientId = "keep-me" };

        var context = new ExtractTokenRequestContext(transaction);
        context.Request = transaction.Request;

        await new ExtractClientCredentialsHandler().HandleAsync(context);

        // Should not modify anything
        context.Request!.ClientId.Should().Be("keep-me");
    }

    // ── Introspection endpoint ──

    [Fact]
    public async Task Introspection_BasicAuth_ExtractsCredentials()
    {
        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string> { ["token"] = "some-token" };
        var creds = Convert.ToBase64String(
            System.Text.Encoding.UTF8.GetBytes("intro-client:intro-secret"));
        exchange.In.Headers["Authorization"] = $"Basic {creds}";

        var transaction = new OpenIddictServerTransaction();
        transaction.Properties[RedbRouteOpenIddictServerHelpers.ExchangePropertyKey] = exchange;
        var context = new ExtractIntrospectionRequestContext(transaction);
        context.Request = RedbRouteOpenIddictServerHelpers.CreateRequestFromExchange(exchange);

        await new ExtractIntrospectionClientCredentialsHandler().HandleAsync(context);

        context.Request!.ClientId.Should().Be("intro-client");
        context.Request.ClientSecret.Should().Be("intro-secret");
    }

    [Fact]
    public async Task Introspection_NoBasicAuth_LeavesUnchanged()
    {
        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["token"] = "some-token",
            ["client_id"] = "body-client"
        };

        var transaction = new OpenIddictServerTransaction();
        transaction.Properties[RedbRouteOpenIddictServerHelpers.ExchangePropertyKey] = exchange;
        var context = new ExtractIntrospectionRequestContext(transaction);
        context.Request = RedbRouteOpenIddictServerHelpers.CreateRequestFromExchange(exchange);

        await new ExtractIntrospectionClientCredentialsHandler().HandleAsync(context);

        context.Request!.ClientId.Should().Be("body-client");
    }

    // ── Revocation endpoint ──

    [Fact]
    public async Task Revocation_BasicAuth_ExtractsCredentials()
    {
        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string> { ["token"] = "revoke-me" };
        var creds = Convert.ToBase64String(
            System.Text.Encoding.UTF8.GetBytes("revoke-client:revoke-secret"));
        exchange.In.Headers["Authorization"] = $"Basic {creds}";

        var transaction = new OpenIddictServerTransaction();
        transaction.Properties[RedbRouteOpenIddictServerHelpers.ExchangePropertyKey] = exchange;
        var context = new ExtractRevocationRequestContext(transaction);
        context.Request = RedbRouteOpenIddictServerHelpers.CreateRequestFromExchange(exchange);

        await new ExtractRevocationClientCredentialsHandler().HandleAsync(context);

        context.Request!.ClientId.Should().Be("revoke-client");
        context.Request.ClientSecret.Should().Be("revoke-secret");
    }

    [Fact]
    public async Task Revocation_NoBasicAuth_LeavesUnchanged()
    {
        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["token"] = "revoke-me",
            ["client_id"] = "body-client"
        };

        var transaction = new OpenIddictServerTransaction();
        transaction.Properties[RedbRouteOpenIddictServerHelpers.ExchangePropertyKey] = exchange;
        var context = new ExtractRevocationRequestContext(transaction);
        context.Request = RedbRouteOpenIddictServerHelpers.CreateRequestFromExchange(exchange);

        await new ExtractRevocationClientCredentialsHandler().HandleAsync(context);

        context.Request!.ClientId.Should().Be("body-client");
    }
}
