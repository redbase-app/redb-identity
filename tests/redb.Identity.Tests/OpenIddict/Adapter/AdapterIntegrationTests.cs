using System.Security.Claims;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using redb.Identity.Core.OpenIddict;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Tests.Adapter;

/// <summary>
/// Integration tests proving the full adapter pipeline works end-to-end:
/// IExchange → Extract handlers → OpenIddict pipeline → Apply handlers → IExchange.Out
/// </summary>
public class AdapterIntegrationTests
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

                // Register our redb.Route adapter
                options.UseRedbRoute();

                // Degraded mode requires a custom validation handler
                options.AddEventHandler<ValidateTokenRequestContext>(builder =>
                    builder
                        .UseInlineHandler(context => default)
                        .SetOrder(int.MaxValue - 100_000)
                        .Build());

                // Custom handler: provide ClaimsPrincipal for client_credentials
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

                            identity.SetClaim(Claims.Subject, context.Request.ClientId!);
                            context.Principal = new ClaimsPrincipal(identity);
                            return default;
                        })
                        .SetOrder(OpenIddictServerHandlers.Exchange.AttachPrincipal
                            .Descriptor.Order + 100)
                        .Build());
            });

        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task ClientCredentials_ViaExchange_ProducesAccessToken()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        // Simulate IExchange from direct-vm://identity-token
        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "test-client",
            ["client_secret"] = "test-secret"
        };

        await handler.ProcessAsync(exchange, OpenIddictServerEndpointType.Token);

        // Verify response written to exchange
        exchange.Out.Should().NotBeNull("Apply handler should write the response");
        exchange.Out!.ContentType.Should().Be("application/json");

        var body = exchange.Out.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body.Should().ContainKey("access_token");
        body["access_token"].Should().NotBeNull();
        body["access_token"]!.ToString().Should().NotBeEmpty("JWT access token should be generated");
        body["token_type"].Should().Be("Bearer");
        body["expires_in"].Should().NotBeNull();
    }

    [Fact]
    public async Task ClientCredentials_ViaBasicAuth_ProducesAccessToken()
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

        await handler.ProcessAsync(exchange, OpenIddictServerEndpointType.Token);

        exchange.Out.Should().NotBeNull();

        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body.Should().ContainKey("access_token");
        body["token_type"].Should().Be("Bearer");
    }

    [Fact]
    public async Task InvalidGrantType_ReturnsError()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["grant_type"] = "password", // not allowed
            ["client_id"] = "test-client",
            ["client_secret"] = "test-secret"
        };

        await handler.ProcessAsync(exchange, OpenIddictServerEndpointType.Token);

        exchange.Out.Should().NotBeNull();

        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body.Should().ContainKey("error");
        body["error"].Should().Be("unsupported_grant_type");
    }
}
