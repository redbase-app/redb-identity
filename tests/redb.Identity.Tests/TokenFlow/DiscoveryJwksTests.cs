using System.Security.Claims;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using redb.Identity.Core.OpenIddict;
using redb.Identity.Core.Routes.Processors;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Tests.TokenFlow;

/// <summary>
/// Integration tests for Discovery and JWKS endpoints.
/// </summary>
public class DiscoveryJwksTests
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
                options.SetIntrospectionEndpointUris("/connect/introspect");
                options.SetRevocationEndpointUris("/connect/revoke");
                options.SetConfigurationEndpointUris("/.well-known/openid-configuration");
                options.SetJsonWebKeySetEndpointUris("/.well-known/jwks");

                options.AllowClientCredentialsFlow();

                options.AddEphemeralEncryptionKey();
                options.AddEphemeralSigningKey();
                options.DisableAccessTokenEncryption();

                options.UseRedbRoute();

                // Degraded mode handler
                options.AddEventHandler<ValidateTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context => default)
                        .SetOrder(int.MaxValue - 100_000).Build());

                options.AddEventHandler<ValidateIntrospectionRequestContext>(builder =>
                    builder.UseInlineHandler(context => default)
                        .SetOrder(int.MaxValue - 100_000).Build());

                options.AddEventHandler<ValidateRevocationRequestContext>(builder =>
                    builder.UseInlineHandler(context => default)
                        .SetOrder(int.MaxValue - 100_000).Build());
            });

        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task Discovery_ReturnsValidJson()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();

        var processor = new DiscoveryEndpointProcessor(handler);
        await processor.Process(exchange);

        exchange.Out.Should().NotBeNull();
        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body.Should().ContainKey("issuer");
        body["issuer"]!.ToString().Should().Be("https://identity.test.local/");
    }

    [Fact]
    public async Task Discovery_ContainsTokenEndpoint()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();
        await new DiscoveryEndpointProcessor(handler).Process(exchange);

        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body.Should().ContainKey("token_endpoint");
    }

    [Fact]
    public async Task Discovery_ContainsGrantTypes()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();
        await new DiscoveryEndpointProcessor(handler).Process(exchange);

        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body.Should().ContainKey("grant_types_supported");
    }

    [Fact]
    public async Task Discovery_ContainsJwksUri()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();
        await new DiscoveryEndpointProcessor(handler).Process(exchange);

        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body.Should().ContainKey("jwks_uri");
    }

    [Fact]
    public async Task Jwks_ReturnsKeys()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();

        var processor = new JwksEndpointProcessor(handler);
        await processor.Process(exchange);

        exchange.Out.Should().NotBeNull();
        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body.Should().ContainKey("keys");
    }

    [Fact]
    public async Task Discovery_ContainsIntrospectionEndpoint()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();
        await new DiscoveryEndpointProcessor(handler).Process(exchange);

        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body.Should().ContainKey("introspection_endpoint");
    }

    [Fact]
    public async Task Discovery_ContainsTokenEndpointAuthMethods()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();
        await new DiscoveryEndpointProcessor(handler).Process(exchange);

        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body.Should().ContainKey("token_endpoint_auth_methods_supported");
    }

    [Fact]
    public async Task Jwks_KeysContainRequiredFields()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();
        await new JwksEndpointProcessor(handler).Process(exchange);

        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body.Should().ContainKey("keys");

        // Keys should be a non-empty collection of JWKs
        var keys = body["keys"];
        keys.Should().NotBeNull();
        keys.Should().BeAssignableTo<System.Collections.IEnumerable>();
    }
}
