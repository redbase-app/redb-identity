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
/// Integration tests for Introspection and Revocation endpoints.
/// Uses degraded mode — token validation is limited, but pipeline path is verified.
/// </summary>
public class IntrospectionRevocationTests
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
                options.SetRevocationEndpointUris("/connect/revocation");
                options.AllowClientCredentialsFlow();

                options.AddEphemeralEncryptionKey();
                options.AddEphemeralSigningKey();
                options.DisableAccessTokenEncryption();

                options.UseRedbRoute();

                // Degraded mode handlers
                options.AddEventHandler<ValidateTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context => default)
                        .SetOrder(int.MaxValue - 100_000).Build());

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
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
                    }).SetOrder(OpenIddictServerHandlers.Exchange.AttachPrincipal
                        .Descriptor.Order + 100).Build());

                // Degraded mode: skip introspection client validation
                options.AddEventHandler<ValidateIntrospectionRequestContext>(builder =>
                    builder.UseInlineHandler(context => default)
                        .SetOrder(int.MaxValue - 100_000).Build());

                // Degraded mode: skip revocation client validation
                options.AddEventHandler<ValidateRevocationRequestContext>(builder =>
                    builder.UseInlineHandler(context => default)
                        .SetOrder(int.MaxValue - 100_000).Build());
            });

        return services.BuildServiceProvider();
    }

    private static async Task<string> ObtainAccessToken(IServiceScope scope)
    {
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();
        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "test-client",
            ["client_secret"] = "test-secret"
        };
        await new TokenEndpointProcessor(handler).Process(exchange);
        var body = (Dictionary<string, object?>)exchange.Out!.Body!;
        return body["access_token"]!.ToString()!;
    }

    // ── Introspection ──

    [Fact]
    public async Task Introspect_ValidToken_ReturnsClaims()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var token = await ObtainAccessToken(scope);

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["token"] = token
        };
        exchange.In.Headers["Authorization"] = "Basic " +
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("test-client:test-secret"));

        await new IntrospectionEndpointProcessor(handler).Process(exchange);

        exchange.Out.Should().NotBeNull();
        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;

        // In degraded mode OpenIddict validates the self-contained JWT directly.
        // It should return active=true and include the subject claim.
        body.Should().ContainKey("active");
        body["active"].Should().Be(true);
        body.Should().ContainKey("sub");
        body["sub"]!.ToString().Should().Be("test-client");
    }

    [Fact]
    public async Task Introspect_ValidToken_ContainsIssuer()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var token = await ObtainAccessToken(scope);

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["token"] = token
        };
        exchange.In.Headers["Authorization"] = "Basic " +
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("test-client:test-secret"));

        await new IntrospectionEndpointProcessor(handler).Process(exchange);

        var body = (Dictionary<string, object?>)exchange.Out!.Body!;
        body.Should().ContainKey("iss");
        body["iss"]!.ToString().Should().Contain("identity.test.local");
    }

    [Fact]
    public async Task Introspect_InvalidToken_ReturnsInactive()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["token"] = "completely-invalid-token"
        };
        exchange.In.Headers["Authorization"] = "Basic " +
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("test-client:test-secret"));

        await new IntrospectionEndpointProcessor(handler).Process(exchange);

        exchange.Out.Should().NotBeNull();
        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        // OpenIddict returns error for completely invalid tokens (not RFC active:false)
        body.Should().ContainKey("error");
    }

    [Fact]
    public async Task Introspect_MissingToken_ReturnsError()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>();
        exchange.In.Headers["Authorization"] = "Basic " +
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("test-client:test-secret"));

        await new IntrospectionEndpointProcessor(handler).Process(exchange);

        exchange.Out.Should().NotBeNull();
        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body.Should().ContainKey("error");
        body["error"].Should().Be("invalid_request");
    }

    // ── Revocation ──

    [Fact]
    public async Task Revoke_ValidToken_ReturnsSuccess()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var token = await ObtainAccessToken(scope);

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["token"] = token
        };
        exchange.In.Headers["Authorization"] = "Basic " +
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("test-client:test-secret"));

        await new RevocationEndpointProcessor(handler).Process(exchange);

        // RFC 7009: always returns 200 (no error means success)
        exchange.Out.Should().NotBeNull();
        var body = exchange.Out!.Body as Dictionary<string, object?>;
        if (body != null)
        {
            body.Should().NotContainKey("error",
                "revocation should not return an error for a valid token");
        }
    }

    [Fact]
    public async Task Revoke_SetsEventMetadata()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var token = await ObtainAccessToken(scope);

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["token"] = token
        };
        exchange.In.Headers["Authorization"] = "Basic " +
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("test-client:test-secret"));

        await new RevocationEndpointProcessor(handler).Process(exchange);

        exchange.Properties.Should().ContainKey("identity-event-type");
        exchange.Properties["identity-event-type"].Should().Be("TokenRevoked");
    }

    [Fact]
    public async Task Revoke_InvalidToken_ReturnsSuccess()
    {
        // RFC 7009 §2.1: The server responds with HTTP 200 even if the token is invalid/unknown.
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["token"] = "not-a-real-token-at-all"
        };
        exchange.In.Headers["Authorization"] = "Basic " +
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("test-client:test-secret"));

        await new RevocationEndpointProcessor(handler).Process(exchange);

        // Revocation should not blow up; handler always sets event metadata
        exchange.Out.Should().NotBeNull();
        exchange.Properties.Should().ContainKey("identity-event-type");
        exchange.Properties["identity-event-type"].Should().Be("TokenRevoked");
    }

    [Fact]
    public async Task Revoke_MissingToken_ReturnsError()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>();
        exchange.In.Headers["Authorization"] = "Basic " +
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("test-client:test-secret"));

        await new RevocationEndpointProcessor(handler).Process(exchange);

        exchange.Out.Should().NotBeNull();
        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body.Should().ContainKey("error");
        body["error"].Should().Be("invalid_request");
    }

    [Fact]
    public async Task Revoke_WithTokenTypeHint_ReturnsSuccess()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var token = await ObtainAccessToken(scope);

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["token"] = token,
            ["token_type_hint"] = "access_token"
        };
        exchange.In.Headers["Authorization"] = "Basic " +
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("test-client:test-secret"));

        await new RevocationEndpointProcessor(handler).Process(exchange);

        exchange.Out.Should().NotBeNull();
        var body = exchange.Out!.Body as Dictionary<string, object?>;
        if (body != null)
        {
            body.Should().NotContainKey("error",
                "revocation with valid token_type_hint should succeed");
        }
    }
}
