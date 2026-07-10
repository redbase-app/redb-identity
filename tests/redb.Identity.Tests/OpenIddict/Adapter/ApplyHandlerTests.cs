using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.OpenIddict;
using redb.Identity.Core.OpenIddict.Handlers;
using redb.Identity.Tests.Infrastructure;
using redb.Route.Abstractions;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Tests.Adapter;

public class ApplyHandlerTests
{
    private static (OpenIddictServerTransaction transaction, TestExchange exchange)
        CreateTransactionWithExchange()
    {
        var exchange = new TestExchange();
        var transaction = new OpenIddictServerTransaction();
        transaction.Properties[RedbRouteOpenIddictServerHelpers.ExchangePropertyKey] = exchange;
        return (transaction, exchange);
    }

    [Fact]
    public async Task ApplyTokenResponse_SuccessResponse_WritesToExchangeOut()
    {
        var (transaction, exchange) = CreateTransactionWithExchange();
        transaction.Response = new OpenIddictResponse();
        transaction.Response.AccessToken = "eyJ-test-token";
        transaction.Response.TokenType = "Bearer";
        transaction.Response.ExpiresIn = 3600;

        var context = new ApplyTokenResponseContext(transaction);
        await new ApplyTokenResponseHandler().HandleAsync(context);

        exchange.Out.Should().NotBeNull();
        exchange.Out!.ContentType.Should().Be("application/json");
        exchange.Pattern.Should().Be(ExchangePattern.InOut);
        context.IsRequestHandled.Should().BeTrue();

        var body = exchange.Out.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body["access_token"].Should().Be("eyJ-test-token");
        body["token_type"].Should().Be("Bearer");
        body["expires_in"].Should().Be(3600L);
    }

    [Fact]
    public async Task ApplyTokenResponse_ErrorResponse_WritesErrorToExchangeOut()
    {
        var (transaction, exchange) = CreateTransactionWithExchange();
        transaction.Response = new OpenIddictResponse
        {
            Error = "invalid_client",
            ErrorDescription = "Unknown client"
        };

        var context = new ApplyTokenResponseContext(transaction);
        await new ApplyTokenResponseHandler().HandleAsync(context);

        exchange.Out.Should().NotBeNull();
        context.IsRequestHandled.Should().BeTrue();

        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body["error"].Should().Be("invalid_client");
        body["error_description"].Should().Be("Unknown client");
    }

    [Fact]
    public async Task ApplyTokenResponse_NoExchange_Skips()
    {
        var transaction = new OpenIddictServerTransaction();
        transaction.Response = new OpenIddictResponse();

        var context = new ApplyTokenResponseContext(transaction);
        await new ApplyTokenResponseHandler().HandleAsync(context);

        context.IsRequestHandled.Should().BeFalse();
    }

    [Fact]
    public async Task ApplyAuthorizationResponse_WritesToExchangeOut()
    {
        var (transaction, exchange) = CreateTransactionWithExchange();
        transaction.Response = new OpenIddictResponse();
        transaction.Response.Code = "auth-code-123";

        var context = new ApplyAuthorizationResponseContext(transaction);
        await new ApplyAuthorizationResponseHandler().HandleAsync(context);

        exchange.Out.Should().NotBeNull();
        context.IsRequestHandled.Should().BeTrue();

        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body["code"].Should().Be("auth-code-123");
    }

    [Fact]
    public async Task ApplyIntrospectionResponse_WritesToExchangeOut()
    {
        var (transaction, exchange) = CreateTransactionWithExchange();
        transaction.Response = new OpenIddictResponse();
        transaction.Response.SetParameter("active", new OpenIddictParameter(true));

        var context = new ApplyIntrospectionResponseContext(transaction);
        await new ApplyIntrospectionResponseHandler().HandleAsync(context);

        exchange.Out.Should().NotBeNull();
        context.IsRequestHandled.Should().BeTrue();
    }

    [Fact]
    public async Task ApplyRevocationResponse_WritesToExchangeOut()
    {
        var (transaction, exchange) = CreateTransactionWithExchange();
        transaction.Response = new OpenIddictResponse();

        var context = new ApplyRevocationResponseContext(transaction);
        await new ApplyRevocationResponseHandler().HandleAsync(context);

        exchange.Out.Should().NotBeNull();
        context.IsRequestHandled.Should().BeTrue();
    }

    [Fact]
    public async Task ApplyDiscoveryResponse_WritesToExchangeOut()
    {
        var (transaction, exchange) = CreateTransactionWithExchange();
        transaction.Response = new OpenIddictResponse();
        transaction.Response.SetParameter("issuer",
            new OpenIddictParameter("https://identity.local/"));

        var context = new ApplyConfigurationResponseContext(transaction);
        await new ApplyDiscoveryResponseHandler(Options.Create(new RedbIdentityOptions())).HandleAsync(context);

        exchange.Out.Should().NotBeNull();
        context.IsRequestHandled.Should().BeTrue();

        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body["issuer"].Should().Be("https://identity.local/");
    }

    [Fact]
    public async Task ApplyUserinfoResponse_WritesToExchangeOut()
    {
        var (transaction, exchange) = CreateTransactionWithExchange();
        transaction.Response = new OpenIddictResponse();
        transaction.Response.SetParameter("sub", new OpenIddictParameter("user-123"));

        var context = new ApplyUserInfoResponseContext(transaction);
        await new ApplyUserinfoResponseHandler().HandleAsync(context);

        exchange.Out.Should().NotBeNull();
        context.IsRequestHandled.Should().BeTrue();

        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body["sub"].Should().Be("user-123");
    }

    [Fact]
    public async Task ApplyTokenResponse_PreservesExistingOut()
    {
        var (transaction, exchange) = CreateTransactionWithExchange();
        transaction.Response = new OpenIddictResponse { AccessToken = "tok" };

        // Pre-create Out message
        exchange.Out = new TestMessage();

        var context = new ApplyTokenResponseContext(transaction);
        await new ApplyTokenResponseHandler().HandleAsync(context);

        // Should reuse existing Out, not create a new one
        exchange.Out.Should().NotBeNull();

        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body["access_token"].Should().Be("tok");
    }

    [Fact]
    public async Task ApplyTokenResponse_NormalizesJsonElementValues()
    {
        var (transaction, exchange) = CreateTransactionWithExchange();
        transaction.Response = new OpenIddictResponse();

        // SetParameter with JsonElement values (as OpenIddict may produce internally)
        transaction.Response.SetParameter("string_val",
            new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("\"hello\"")));
        transaction.Response.SetParameter("number_val",
            new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("42")));
        transaction.Response.SetParameter("bool_val",
            new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("true")));

        var context = new ApplyTokenResponseContext(transaction);
        await new ApplyTokenResponseHandler().HandleAsync(context);

        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;

        // JsonElement should be unwrapped to native types, not left as JsonElement
        body["string_val"].Should().BeOfType<string>().And.Be("hello");
        body["number_val"].Should().NotBeOfType<JsonElement>("numbers should be unwrapped");
        Convert.ToInt64(body["number_val"]).Should().Be(42L);
        body["bool_val"].Should().BeOfType<bool>().And.Be(true);
    }
}
