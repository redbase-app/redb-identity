using System.Security.Claims;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Tests.Spike;

/// <summary>
/// Phase 1b critical spike: prove OpenIddict Server pipeline can process
/// client_credentials grant WITHOUT HttpContext, using only
/// IOpenIddictServerFactory + IOpenIddictServerDispatcher.
/// </summary>
public class AdapterSpikeTests
{
    /// <summary>
    /// Minimal spike: degraded mode, no database, no stores.
    /// Proves the pipeline mechanics work end-to-end without HTTP.
    /// </summary>
    [Fact]
    public async Task ClientCredentials_DegradedMode_ProducesAccessToken()
    {
        // Arrange — build DI container with OpenIddict Server in degraded mode
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddConsole().SetMinimumLevel(LogLevel.Debug));

        services.AddOpenIddict()
            .AddServer(options =>
            {
                // Degraded mode: no stores, no entity validation
                options.EnableDegradedMode();

                // Required configuration
                options.SetIssuer(new Uri("https://identity.test.local/"));
                options.SetTokenEndpointUris("/connect/token");
                options.AllowClientCredentialsFlow();

                // Ephemeral keys for testing (in-memory RSA)
                options.AddEphemeralEncryptionKey();
                options.AddEphemeralSigningKey();

                // Disable token/authorization storage (no stores in degraded mode)
                options.DisableAccessTokenEncryption();

                // Handler 0: degraded-mode requires a custom validation handler
                options.AddEventHandler<ValidateTokenRequestContext>(builder =>
                    builder
                        .UseInlineHandler(context =>
                        {
                            // In a real adapter, validate client_id/secret here.
                            // For the spike, accept everything.
                            return default;
                        })
                        .SetOrder(int.MaxValue - 100_000)
                        .Build());

                // Handler 1: provide ClaimsPrincipal for client_credentials
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

                // Handler 2: prevent ApplyTokenResponse from throwing ID0042
                options.AddEventHandler<ApplyTokenResponseContext>(builder =>
                    builder
                        .UseInlineHandler(context =>
                        {
                            context.HandleRequest();
                            return default;
                        })
                        .SetOrder(int.MinValue + 100_000)
                        .Build());
            });

        await using var sp = services.BuildServiceProvider();
        using var scope = sp.CreateScope();

        var factory = scope.ServiceProvider.GetRequiredService<IOpenIddictServerFactory>();
        var dispatcher = scope.ServiceProvider
            .GetRequiredService<IOpenIddictServerDispatcher>();

        // Act — create transaction and drive the pipeline manually
        var transaction = await factory.CreateTransactionAsync();

        // Pre-set the endpoint type (InferEndpointType will skip since no URIs)
        transaction.EndpointType = OpenIddictServerEndpointType.Token;

        // Pre-set the request (replaces host-specific Extract handler)
        transaction.Request = new OpenIddictRequest
        {
            GrantType = GrantTypes.ClientCredentials,
            ClientId = "spike-client",
            ClientSecret = "spike-secret"
        };

        var context = new ProcessRequestContext(transaction);
        await dispatcher.DispatchAsync(context);

        // Assert — pipeline completed and produced a token
        context.IsRequestHandled.Should().BeTrue(
            "the pipeline should complete successfully without HttpContext");

        transaction.Response.Should().NotBeNull(
            "the pipeline should produce a response");

        transaction.Response!.AccessToken.Should().NotBeNullOrEmpty(
            "a JWT access token should be generated for client_credentials");

        transaction.Response.TokenType.Should().Be("Bearer");

        transaction.Response.Error.Should().BeNullOrEmpty(
            "there should be no error in the response");

        transaction.Response.ExpiresIn.Should().BeGreaterThan(0,
            "the token should have a positive expiration");
    }
}
