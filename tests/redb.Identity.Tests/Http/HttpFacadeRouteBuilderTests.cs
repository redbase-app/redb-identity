using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using NSubstitute;
using OpenIddict.Server;
using redb.Core;
using redb.Identity.Contracts.Configuration;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.OpenIddict;
using redb.Identity.Core.Services;
using redb.Identity.Http;
using redb.Identity.Http.Security;
using redb.Route.Abstractions;
using redb.Route.Definitions;
using Xunit;

namespace redb.Identity.Tests.Http;

public class HttpFacadeRouteBuilderTests
{
    private readonly HttpFacadeRouteBuilder _builder;

    public HttpFacadeRouteBuilderTests()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(Substitute.For<IRedbService>());
        services.AddSingleton(Options.Create(new RedbIdentityOptions()));
        services.AddSingleton(Options.Create(new IdentityTransportOptions()));
        services.AddDataProtection().UseEphemeralDataProtectionProvider();

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
            });

        var sp = services.BuildServiceProvider();
        var ticketService = new SessionTicketService(sp.GetRequiredService<IDataProtectionProvider>());
        _builder = new HttpFacadeRouteBuilder(
            ticketService,
            sp.GetRequiredService<IOptions<IdentityTransportOptions>>());
        ((IRouteBuilder)_builder).Configure(null!);
    }

    [Fact]
    public void Configure_DoesNotThrow()
    {
        _builder.Definitions.Should().NotBeEmpty();
    }

    [Fact]
    public void Protocol_Routes_Have_Correct_Count()
    {
        // Always-mounted protocol routes with the fixture's default options
        // (Features = all-off, so ConfigureScimApi, federation-providers/public,
        // ConfigurePublicFederationProvidersEndpoint, the /scim/v2 resource routes,
        // PAR, DCR, device-code, and all other feature-gated mounts are absent):
        //
        //   token, authorize-get, authorize-post, login-get, login-post,
        //   consent-get, consent-post, userinfo-get, userinfo-post,
        //   revoke, introspect, discovery (OIDC), discovery-oauth (RFC 8414),
        //   jwks, management,
        //   logout-get, logout-post,
        //   mfa-get, mfa-post, mfa-recovery-get, mfa-recovery-post,
        //   mfa-challenge-post, mfa-methods-post,
        //   bootstrap-admin (B1 emergency-admin endpoint, mounted on management port),
        //   scim/v2/ServiceProviderConfig, scim/v2/ResourceTypes, scim/v2/Schemas,
        //   scim/v2/ResourceTypes/{id}, scim/v2/Schemas/{id}
        //     (RFC 7644 §4 SCIM discovery — unauthenticated and mounted UNCONDITIONALLY
        //      on the management port so RPs can discover the SCIM surface even when
        //      EnableScim=false; the resource endpoints under /scim/v2 stay gated.
        //      The two single-resource routes were missing: a provisioning client is pointed
        //      at ONE base URL, walks ResourceTypes and then fetches each Schema BY ID —
        //      which 404'd. Same registry, same controller; only the routes were absent.)
        //                                                                                  = 29
        _builder.Definitions.Should().HaveCount(29);
    }

    [Theory]
    [InlineData("http-token")]
    [InlineData("http-authorize-get")]
    [InlineData("http-authorize-post")]
    [InlineData("http-userinfo-get")]
    [InlineData("http-userinfo-post")]
    [InlineData("http-revoke")]
    [InlineData("http-introspect")]
    [InlineData("http-discovery")]
    [InlineData("http-jwks")]
    [InlineData("http-management-api")]
    public void Route_With_Id_Exists(string routeId)
    {
        _builder.Definitions
            .Select(d => d.GetRouteId())
            .Should().Contain(routeId);
    }

    [Theory]
    [InlineData("http-token", "/connect/token")]
    [InlineData("http-authorize-get", "/connect/authorize")]
    [InlineData("http-authorize-post", "/connect/authorize")]
    [InlineData("http-userinfo-get", "/connect/userinfo")]
    [InlineData("http-userinfo-post", "/connect/userinfo")]
    [InlineData("http-revoke", "/connect/revocation")]
    [InlineData("http-introspect", "/connect/introspect")]
    [InlineData("http-discovery", "/.well-known/openid-configuration")]
    [InlineData("http-jwks", "/.well-known/jwks")]
    public void Protocol_Route_FromUri_ContainsExpectedPath(string routeId, string expectedPath)
    {
        var route = _builder.Definitions.First(d => d.GetRouteId() == routeId);
        route.GetFromUri().Should().Contain(expectedPath);
    }

    [Fact]
    public void Management_Route_Uses_CatchAll_Path()
    {
        var route = _builder.Definitions.First(d => d.GetRouteId() == "http-management-api");
        var fromUri = route.GetFromUri();
        fromUri.Should().Contain("/api/v1/identity/{**path}");
        fromUri.Should().Contain("inOut=true");
    }

    [Fact]
    public void CustomPort_Config_Reflected_In_Routes()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(Substitute.For<IRedbService>());
        services.AddSingleton(Options.Create(new RedbIdentityOptions()));
        services.AddSingleton(Options.Create(new IdentityTransportOptions
        {
            Http = new HttpTransportOptions { PublicPort = 9090 }
        }));
        services.AddDataProtection().UseEphemeralDataProtectionProvider();

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
            });

        var sp = services.BuildServiceProvider();
        var ts = new SessionTicketService(sp.GetRequiredService<IDataProtectionProvider>());
        var builder = new HttpFacadeRouteBuilder(
            ts,
            sp.GetRequiredService<IOptions<IdentityTransportOptions>>());
        ((IRouteBuilder)builder).Configure(null!);

        builder.Definitions.Should().AllSatisfy(d =>
            d.GetFromUri().Should().Contain("9090"));
    }

    [Fact]
    public void SeparateManagementPort_Config_Works()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(Substitute.For<IRedbService>());
        services.AddSingleton(Options.Create(new RedbIdentityOptions()));
        services.AddSingleton(Options.Create(new IdentityTransportOptions
        {
            Http = new HttpTransportOptions
            {
                PublicPort = 8080,
                ManagementPort = 8081
            }
        }));
        services.AddDataProtection().UseEphemeralDataProtectionProvider();

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
            });

        var sp = services.BuildServiceProvider();
        var ts = new SessionTicketService(sp.GetRequiredService<IDataProtectionProvider>());
        var builder = new HttpFacadeRouteBuilder(
            ts,
            sp.GetRequiredService<IOptions<IdentityTransportOptions>>());
        ((IRouteBuilder)builder).Configure(null!);

        var mgmtRoute = builder.Definitions.First(d => d.GetRouteId() == "http-management-api");
        mgmtRoute.GetFromUri().Should().Contain("8081");

        var tokenRoute = builder.Definitions.First(d => d.GetRouteId() == "http-token");
        tokenRoute.GetFromUri().Should().Contain("8080");
    }

    // ── Conditional feature routes ──

    [Fact]
    public void DynamicRegistration_Disabled_NoRegisterRoute()
    {
        // Default builder has EnableDynamicRegistration=false
        _builder.Definitions
            .Select(d => d.GetRouteId())
            .Should().NotContain("http-dynamic-register");
    }

    [Fact]
    public void DynamicRegistration_Enabled_RegisterRouteExists()
    {
        var builder = CreateBuilder(
            transport: new IdentityTransportOptions { Features = new IdentityFeatureFlags { EnableDynamicRegistration = true } });

        builder.Definitions
            .Select(d => d.GetRouteId())
            .Should().Contain("http-dynamic-register");
    }

    [Fact]
    public void DynamicRegistration_Enabled_RegisterRoute_PointsToConnectRegister()
    {
        var builder = CreateBuilder(
            transport: new IdentityTransportOptions { Features = new IdentityFeatureFlags { EnableDynamicRegistration = true } });

        var route = builder.Definitions.First(d => d.GetRouteId() == "http-dynamic-register");
        route.GetFromUri().Should().Contain("/connect/register");
    }

    [Fact]
    public void DeviceCodeFlow_Disabled_NoDeviceRoutes()
    {
        // Default builder has EnableDeviceCodeFlow=false
        _builder.Definitions
            .Select(d => d.GetRouteId())
            .Should().NotContain(id => id.Contains("device", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void DeviceCodeFlow_Enabled_DeviceRouteExists()
    {
        var builder = CreateBuilder(
            transport: new IdentityTransportOptions
            {
                Features = new IdentityFeatureFlags { EnableDeviceCodeFlow = true }
            });

        builder.Definitions
            .Select(d => d.GetRouteId())
            .Should().Contain(id => id.Contains("device", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void DynamicRegistration_Enabled_RouteCount_Increases()
    {
        var defaultCount = _builder.Definitions.Count;

        var builder = CreateBuilder(
            transport: new IdentityTransportOptions { Features = new IdentityFeatureFlags { EnableDynamicRegistration = true } });

        builder.Definitions.Count.Should().Be(defaultCount + 2,
            "enabling dynamic registration should add the registration and management routes (RFC 7591 + 7592)");
    }

    private static HttpFacadeRouteBuilder CreateBuilder(
        RedbIdentityOptions? identity = null,
        IdentityTransportOptions? transport = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(Substitute.For<IRedbService>());
        services.AddSingleton(Options.Create(identity ?? new RedbIdentityOptions()));
        services.AddSingleton(Options.Create(transport ?? new IdentityTransportOptions()));
        services.AddDataProtection().UseEphemeralDataProtectionProvider();

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
            });

        var sp = services.BuildServiceProvider();
        var ts = new SessionTicketService(sp.GetRequiredService<IDataProtectionProvider>());
        var builder = new HttpFacadeRouteBuilder(
            ts,
            sp.GetRequiredService<IOptions<IdentityTransportOptions>>());
        ((IRouteBuilder)builder).Configure(null!);
        return builder;
    }
}
