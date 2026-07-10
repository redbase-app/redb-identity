using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using redb.Core;
using redb.Core.Providers;
using redb.Identity.Core;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.OpenIddict;
using redb.Identity.Contracts.Routes;
using redb.Route.Abstractions;
using redb.Route.Components;
using redb.Route.Core;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using redb.Identity.Core.Routes;

namespace redb.Identity.Tests.Infrastructure;

/// <summary>
/// Shared fixture that boots a full RouteContext with all 13 Identity routes.
/// Uses OpenIddict degraded mode + mocked IRedbService.
/// Tests send messages via ProducerTemplate through direct-vm:// — exercises the complete pipeline:
/// error handling → throttle → processor → WireTap → event dispatch.
/// </summary>
public sealed class IdentityRouteFixture : IAsyncLifetime
{
    private ServiceProvider _sp = null!;
    private RouteContext _ctx = null!;

    public ProducerTemplate Producer { get; private set; } = null!;
    public IRedbService Redb { get; private set; } = null!;
    public IServiceProvider ServiceProvider => _sp;

    public async Task InitializeAsync()
    {
        var services = new ServiceCollection();

        // Logging
        services.AddLogging(b => b.SetMinimumLevel(LogLevel.Warning));

        // Mocked IRedbService
        Redb = Substitute.For<IRedbService>();
        var userProvider = Substitute.For<IUserProvider>();
        Redb.UserProvider.Returns(userProvider);
        services.AddSingleton(Redb);

        // SharedVmRegistry (required for direct-vm)
        services.AddSingleton<SharedVmRegistry>();

        // DataProtection + MFA protectors — required by IdentityCoreRouteBuilder.Configure()
        // even when no MFA tests run.
        services.AddDataProtection().UseEphemeralDataProtectionProvider();
        services.AddSingleton<redb.Identity.Core.Services.MfaStateProtector>();
        services.AddSingleton<redb.Identity.Core.Services.MfaSetupTokenProtector>();
        services.AddSingleton<redb.Identity.Core.Services.MfaSecretProtector>();

        // Identity options
        services.AddSingleton(Options.Create(new RedbIdentityOptions
        {
            TokenRetentionDays = 30,
            TokenThrottleMaxPerPeriod = 100, // relaxed for tests
            TokenThrottlePeriod = TimeSpan.FromSeconds(1)
        }));

        // OpenIddict in degraded mode
        services.AddOpenIddict()
            .AddCore(core => core.UseRedbStores())
            .AddServer(options =>
            {
                options.EnableDegradedMode();
                options.SetIssuer(new Uri("https://identity.test.local/"));

                options.SetTokenEndpointUris("/connect/token");
                options.SetAuthorizationEndpointUris("/connect/authorize");
                options.SetIntrospectionEndpointUris("/connect/introspect");
                options.SetRevocationEndpointUris("/connect/revoke");
                options.SetConfigurationEndpointUris("/.well-known/openid-configuration");

                options.AllowClientCredentialsFlow();
                options.AllowAuthorizationCodeFlow();
                options.AllowRefreshTokenFlow();

                options.AddEphemeralEncryptionKey();
                options.AddEphemeralSigningKey();
                options.DisableAccessTokenEncryption();

                options.UseRedbRoute();

                // Degraded mode: skip validation for all enabled endpoints
                options.AddEventHandler<ValidateTokenRequestContext>(builder =>
                    builder
                        .UseInlineHandler(context => default)
                        .SetOrder(int.MaxValue - 100_000)
                        .Build());

                options.AddEventHandler<ValidateAuthorizationRequestContext>(builder =>
                    builder
                        .UseInlineHandler(context => default)
                        .SetOrder(int.MaxValue - 100_000)
                        .Build());

                options.AddEventHandler<ValidateIntrospectionRequestContext>(builder =>
                    builder
                        .UseInlineHandler(context => default)
                        .SetOrder(int.MaxValue - 100_000)
                        .Build());

                options.AddEventHandler<ValidateRevocationRequestContext>(builder =>
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

        _sp = services.BuildServiceProvider();

        // Create RouteContext with full DI
        _ctx = new RouteContext(_sp, "identity-integration");

        // Register all 13 identity routes
        _ctx.AddRoutes(new IdentityCoreRouteBuilder(_sp, Options.Create(new RedbIdentityOptions
        {
            TokenThrottleMaxPerPeriod = 100,
            TokenThrottlePeriod = TimeSpan.FromSeconds(1),
            TokenRetentionDays = 30
        })));

        await _ctx.Start();

        Producer = new ProducerTemplate(_ctx);
        Producer.Start();
    }

    public async Task DisposeAsync()
    {
        Producer.Stop();
        Producer.Dispose();
        await _ctx.DisposeAsync();
        await _sp.DisposeAsync();
    }

    /// <summary>
    /// Sends a request through the route pipeline with InOut pattern (returns Out.Body).
    /// </summary>
    public async Task<object?> Request(string endpointUri, object body)
    {
        return await Producer.RequestBody(endpointUri, body);
    }

    /// <summary>
    /// Sends a request with custom headers (e.g. operation header for management endpoints).
    /// Returns the full exchange for inspection.
    /// </summary>
    public async Task<Exchange> RequestWithHeaders(
        string endpointUri, object? body, IDictionary<string, object?> headers)
    {
        var message = new Message { Body = body };
        foreach (var (key, value) in headers)
            message.Headers[key] = value;

        var exchange = new Exchange(message) { Pattern = ExchangePattern.InOut };

        var endpoint = _ctx.GetEndpoint(endpointUri);
        var producer = endpoint.CreateProducer();
        await producer.Process(exchange);

        // Identity convention: business processors write the response into exchange.In.Body
        // and PipelineProcessor (Camel-compliant) does not synthesise Out from In. Tests
        // historically read exchange.Out?.Body directly, so normalise Out := copy-of-In here.
        NormalizeOutFromIn(exchange);

        return exchange;
    }

    private static void NormalizeOutFromIn(Exchange exchange)
    {
        if (exchange.Out is not null) return;
        var inMsg = exchange.In;
        if (inMsg is null) return;
        var outMsg = new Message { Body = inMsg.Body, ContentType = inMsg.ContentType };
        foreach (var (k, v) in inMsg.Headers) outMsg.Headers[k] = v;
        exchange.Out = outMsg;
    }
}

[CollectionDefinition("IdentityRoute")]
public class IdentityRouteCollection : ICollectionFixture<IdentityRouteFixture>;
