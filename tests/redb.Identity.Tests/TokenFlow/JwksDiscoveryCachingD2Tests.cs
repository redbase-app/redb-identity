using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenIddict.Server;
using redb.Identity.Core.OpenIddict;
using redb.Identity.Core.Routes.Processors;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Tests.TokenFlow;

/// <summary>
/// D2 — JWKS rotation/caching headers per OIDC Core §10.1.1.
/// Verifies Cache-Control + Vary headers are emitted by the JWKS and Discovery
/// processors so RPs can cache the documents safely while remaining able to
/// pick up rotation within the overlap window.
/// </summary>
public class JwksDiscoveryCachingD2Tests
{
    private static ServiceProvider BuildSp()
    {
        var services = new ServiceCollection();
        services.AddLogging(b => b.SetMinimumLevel(LogLevel.Warning));

        services.AddOpenIddict()
            .AddServer(options =>
            {
                options.EnableDegradedMode();
                options.SetIssuer(new Uri("https://identity.test.local/"));
                options.SetTokenEndpointUris("/connect/token");
                options.SetConfigurationEndpointUris("/.well-known/openid-configuration");
                options.SetJsonWebKeySetEndpointUris("/.well-known/jwks");
                options.AllowClientCredentialsFlow();
                options.AddEphemeralEncryptionKey();
                options.AddEphemeralSigningKey();
                options.DisableAccessTokenEncryption();
                options.UseRedbRoute();

                options.AddEventHandler<ValidateTokenRequestContext>(b =>
                    b.UseInlineHandler(_ => default).SetOrder(int.MaxValue - 100_000).Build());
            });

        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task Jwks_EmitsCacheControlAndVaryHeaders()
    {
        await using var sp = BuildSp();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();
        await new JwksEndpointProcessor(handler).Process(exchange);

        exchange.Out.Should().NotBeNull();
        exchange.Out!.Headers.Should().ContainKey("Cache-Control");
        exchange.Out.Headers["Cache-Control"]!.ToString()
            .Should().Be("public, max-age=3600",
                "RPs cache JWKS for an hour — well within the 24-72h rotation overlap window");
        exchange.Out.Headers.Should().ContainKey("Vary");
    }

    [Fact]
    public async Task Discovery_EmitsCacheControlAndVaryHeaders()
    {
        await using var sp = BuildSp();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();
        await new DiscoveryEndpointProcessor(handler).Process(exchange);

        exchange.Out.Should().NotBeNull();
        exchange.Out!.Headers.Should().ContainKey("Cache-Control");
        exchange.Out.Headers["Cache-Control"]!.ToString()
            .Should().Be("public, max-age=300",
                "discovery doc is more configuration-mutable so a shorter TTL is appropriate");
        exchange.Out.Headers.Should().ContainKey("Vary");
    }
}
