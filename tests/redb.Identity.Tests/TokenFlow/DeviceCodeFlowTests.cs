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
/// Unit tests for the Device Authorization endpoint (RFC 8628).
/// Uses OpenIddict degraded mode — validates the pipeline path:
/// IExchange → Extract handlers → OpenIddict pipeline → Apply handlers → IExchange.Out
/// </summary>
public class DeviceCodeFlowTests
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
                options.SetDeviceAuthorizationEndpointUris("/connect/deviceauthorization");
                options.SetEndUserVerificationEndpointUris("/connect/device/verify");
                options.SetTokenEndpointUris("/connect/token");
                options.AllowDeviceAuthorizationFlow();

                options.AddEphemeralEncryptionKey();
                options.AddEphemeralSigningKey();
                options.DisableAccessTokenEncryption();

                options.UseRedbRoute();

                // Degraded mode: skip client validation for device authorization
                options.AddEventHandler<ValidateDeviceAuthorizationRequestContext>(builder =>
                    builder
                        .UseInlineHandler(context => default)
                        .SetOrder(int.MaxValue - 100_000)
                        .Build());

                // Degraded mode: skip token validation (required when device flow enabled)
                options.AddEventHandler<ValidateTokenRequestContext>(builder =>
                    builder
                        .UseInlineHandler(context => default)
                        .SetOrder(int.MaxValue - 100_000)
                        .Build());

                // Degraded mode: skip verification validation (required when verification endpoint set)
                options.AddEventHandler<ValidateEndUserVerificationRequestContext>(builder =>
                    builder
                        .UseInlineHandler(context => default)
                        .SetOrder(int.MaxValue - 100_000)
                        .Build());

                // Degraded mode: custom token/code validation (device+user codes have no backing store)
                options.AddEventHandler<ValidateTokenContext>(builder =>
                    builder
                        .UseInlineHandler(context => default)
                        .SetOrder(int.MaxValue - 100_000)
                        .Build());

                // Degraded mode: generate device/user codes in memory
                options.AddEventHandler<GenerateTokenContext>(builder =>
                    builder
                        .UseInlineHandler(context =>
                        {
                            context.Token = Guid.NewGuid().ToString("N");
                            return default;
                        })
                        .SetOrder(int.MaxValue - 100_000)
                        .Build());
            });

        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task DeviceAuthorization_ReturnsExpectedResponseFields()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["client_id"] = "device-test-client"
        };

        var processor = new DeviceEndpointProcessor(handler);
        await processor.Process(exchange);

        exchange.Out.Should().NotBeNull();
        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;

        body.Should().ContainKey("device_code");
        body["device_code"]!.ToString().Should().NotBeEmpty();

        body.Should().ContainKey("user_code");
        body["user_code"]!.ToString().Should().NotBeEmpty();

        body.Should().ContainKey("verification_uri");

        body.Should().ContainKey("expires_in");
    }

    [Fact]
    public async Task DeviceAuthorization_SetsEventMetadata()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["client_id"] = "device-test-client"
        };

        var processor = new DeviceEndpointProcessor(handler);
        await processor.Process(exchange);

        exchange.Properties.Should().ContainKey("identity-event-type");
        exchange.Properties["identity-event-type"].Should().Be("DeviceCodeIssued");
    }
}
