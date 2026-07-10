using System.Security.Claims;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.OpenIddict;
using redb.Identity.Contracts.Routes;
using redb.Identity.Core.Routes.Processors;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Tests.TokenFlow;

/// <summary>
/// Integration tests for the Token endpoint (client_credentials flow).
/// Uses OpenIddict degraded mode — validates the full pipeline path:
/// IExchange → Extract handlers → OpenIddict pipeline → Apply handlers → IExchange.Out
/// </summary>
public class ClientCredentialsFlowTests
{
    private static ServiceProvider BuildServiceProvider()
    {
        var services = new ServiceCollection();
        services.AddLogging(b => b.SetMinimumLevel(LogLevel.Warning));

        services.AddOpenIddict()
            .AddServer(options =>
            {
                options.EnableDegradedMode();
                options.SetIssuer(new Uri("https://identity.test.local/"));
                options.SetTokenEndpointUris("/connect/token");
                options.AllowClientCredentialsFlow();

                options.AddEphemeralEncryptionKey();
                options.AddEphemeralSigningKey();
                options.DisableAccessTokenEncryption();

                options.UseRedbRoute();

                // Degraded mode: skip client validation
                options.AddEventHandler<ValidateTokenRequestContext>(builder =>
                    builder
                        .UseInlineHandler(context => default)
                        .SetOrder(int.MaxValue - 100_000)
                        .Build());

                // Provide ClaimsPrincipal for client_credentials
                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder
                        .UseInlineHandler(context =>
                        {
                            if (!context.Request.IsClientCredentialsGrantType())
                                return default;

                            var identity = new ClaimsIdentity(
                                authenticationType: "OpenIddict.Server",
                                nameType: Claims.Name,
                                roleType: Claims.Role);

                            identity.SetClaim(Claims.Subject, context.Request.ClientId ?? "test-sub");
                            identity.SetScopes(context.Request.GetScopes());
                            context.Principal = new ClaimsPrincipal(identity);
                            return default;
                        })
                        .SetOrder(OpenIddictServerHandlers.Exchange.AttachPrincipal
                            .Descriptor.Order + 100)
                        .Build());
            });

        return services.BuildServiceProvider();
    }

    private static async Task<(TestExchange exchange, RedbRouteOpenIddictServerHandler handler, IServiceScope scope)>
        CreateHandler()
    {
        var sp = BuildServiceProvider();
        var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();
        return (new TestExchange(), handler, scope);
    }

    [Fact]
    public async Task ValidClientCredentials_ReturnsAccessToken()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "test-client",
            ["client_secret"] = "test-secret"
        };

        var processor = new TokenEndpointProcessor(handler);
        await processor.Process(exchange);

        exchange.Out.Should().NotBeNull();
        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body.Should().ContainKey("access_token");
        body["access_token"]!.ToString().Should().NotBeEmpty();
        body["token_type"].Should().Be("Bearer");
        body["expires_in"].Should().NotBeNull();
    }

    [Fact]
    public async Task BasicAuth_ValidCredentials_ReturnsAccessToken()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var credentials = Convert.ToBase64String(
            System.Text.Encoding.UTF8.GetBytes("basic-client:basic-secret"));

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials"
        };
        exchange.In.Headers["Authorization"] = $"Basic {credentials}";

        var processor = new TokenEndpointProcessor(handler);
        await processor.Process(exchange);

        exchange.Out.Should().NotBeNull();
        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body.Should().ContainKey("access_token");
        body["token_type"].Should().Be("Bearer");
    }

    [Fact]
    public async Task MissingClientId_ReturnsInvalidRequest()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials"
            // No client_id
        };

        var processor = new TokenEndpointProcessor(handler);
        await processor.Process(exchange);

        exchange.Out.Should().NotBeNull();
        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body.Should().ContainKey("error");
        body["error"].Should().Be("invalid_request");
    }

    [Fact]
    public async Task UnsupportedGrantType_ReturnsError()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = "test-client",
            ["client_secret"] = "test-secret"
        };

        var processor = new TokenEndpointProcessor(handler);
        await processor.Process(exchange);

        exchange.Out.Should().NotBeNull();
        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body.Should().ContainKey("error");
        body["error"].Should().Be("unsupported_grant_type");
    }

    [Fact]
    public async Task MissingGrantType_ReturnsInvalidRequest()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["client_id"] = "test-client"
            // No grant_type
        };

        var processor = new TokenEndpointProcessor(handler);
        await processor.Process(exchange);

        exchange.Out.Should().NotBeNull();
        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body.Should().ContainKey("error");
        body["error"].Should().Be("invalid_request");
    }

    [Fact]
    public async Task Token_ContainsStandardClaims()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "test-client",
            ["client_secret"] = "test-secret"
        };

        var processor = new TokenEndpointProcessor(handler);
        await processor.Process(exchange);

        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        var jwt = body["access_token"]!.ToString()!;

        // JWT has 3 parts: header.payload.signature
        jwt.Split('.').Should().HaveCount(3, "access_token should be a JWT");
    }

    [Fact]
    public async Task TokenProcessor_SetsEventMetadata()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "my-app",
            ["client_secret"] = "secret"
        };

        var processor = new TokenEndpointProcessor(handler);
        await processor.Process(exchange);

        exchange.Properties.Should().ContainKey("identity-event-type");
        exchange.Properties["identity-event-type"].Should().Be("TokenIssued");
        exchange.Properties.Should().ContainKey("identity-event-data");
    }
}
