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
using redb.Identity.Contracts.Routes;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Definitions;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;
using redb.Identity.Core.Routes;

namespace redb.Identity.Tests.Routes;

public class RouteRegistrationTests
{
    private readonly IdentityCoreRouteBuilder _builder;

    public RouteRegistrationTests()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(Substitute.For<IRedbService>());
        services.AddSingleton(Options.Create(new RedbIdentityOptions()));

        // MFA protectors required by IdentityCoreRouteBuilder.Configure().
        services.AddDataProtection().UseEphemeralDataProtectionProvider();
        services.AddSingleton<MfaStateProtector>();
        services.AddSingleton<MfaSetupTokenProtector>();
        services.AddSingleton<MfaSecretProtector>();

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

                options.AddEventHandler<ValidateTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context => default)
                        .SetOrder(int.MaxValue - 100_000).Build());
            });

        var sp = services.BuildServiceProvider();

        _builder = new IdentityCoreRouteBuilder(sp, sp.GetRequiredService<IOptions<RedbIdentityOptions>>());
        ((IRouteBuilder)_builder).Configure(null!);
    }

    [Fact]
    public void Configure_DoesNotThrow()
    {
        // Already called in constructor — if we got here, it didn't throw.
        _builder.Definitions.Should().NotBeEmpty();
    }

    [Fact]
    public void AllRoutes_Count_Is_45()
    {
        // 25 OIDC/MFA routes + 2 cleanup timer routes added by B3 hardening
        // (identity-mfa-otp-cleanup) and A1 (identity-xml-refresh, materialized via
        // redb.Route TimerDsl → separate RouteDefinition) + 1 admin audit query route
        // (identity-manage-audit) added by H9 (v1.0 DoD) + 1 self-service sessions route
        // (identity-me-sessions) added by H3-SSO (v1.0 DoD §6 scoped-subset) + 4
        // self-service account-console routes (identity-me-profile/password/mfa/consents)
        // added by H3 full closure (v1.0 DoD §6) + 2 H5 admin routes
        // (identity-manage-claim-mappers, identity-manage-claim-scopes) + 2 H8 federation
        // routes (identity-me-federated-identities, identity-manage-federation-providers)
        // + 3 unconditional routes added later (token-cleanup, session-cleanup,
        // mfa-otp-cleanup are timer routes; trusted-proxy-resolver wires HTTP transport)
        // + 1 B1 emergency-admin bootstrap route (identity-bootstrap-admin) registered
        // unconditionally; processor self-disables when BootstrapOptions.Enabled=false.
        // + 2 W6-0 backchannel routes (identity-revoked-sids manage + identity-revoked-sids-cleanup timer).
        // + 2 N-4 password-recovery routes (identity-password-forgot + identity-password-reset).
        //   The identity-email-send SMTP route is NOT counted here: RedbIdentityOptions defaults to
        //   Smtp.Enabled=false so the route is conditionally skipped.
        // + 1 N7-3 admin impersonation overlay route (identity-manage-impersonation), unconditional.
        // + 1 B.3 role management (identity-manage-roles).
        // + 1 S2 claim-definitions management (identity-manage-claim-definitions).
        // + 1 W1 webhook subscription management (identity-manage-webhooks).
        //   Total → 46 + 3 = 49.
        _builder.Definitions.Should().HaveCount(49);
    }

    [Fact]
    public void AllRoutes_HaveRouteIds()
    {
        foreach (var def in _builder.Definitions)
        {
            def.GetRouteId().Should().NotBeNullOrWhiteSpace(
                $"route from '{def.GetFromUri()}' must have a RouteId");
        }
    }

    [Fact]
    public void AllRouteIds_AreUnique()
    {
        var ids = _builder.Definitions.Select(d => d.GetRouteId()).ToList();
        ids.Should().OnlyHaveUniqueItems();
    }

    [Fact]
    public void AllRoutes_RegisteredWithCorrectUris()
    {
        var uris = _builder.Definitions.Select(d => d.GetFromUri()).ToList();

        uris.Should().Contain(IdentityEndpoints.Token);
        uris.Should().Contain(IdentityEndpoints.Authorize);
        uris.Should().Contain(IdentityEndpoints.Userinfo);
        uris.Should().Contain(IdentityEndpoints.Introspect);
        uris.Should().Contain(IdentityEndpoints.Revoke);
        uris.Should().Contain(IdentityEndpoints.Discovery);
        uris.Should().Contain(IdentityEndpoints.Jwks);
        uris.Should().Contain(IdentityEndpoints.ManageApps);
        uris.Should().Contain(IdentityEndpoints.ManageScopes);
        uris.Should().Contain(IdentityEndpoints.ManageUsers);
        uris.Should().Contain(IdentityEndpoints.ManageTokens);
        uris.Should().Contain(IdentityEndpoints.ManageGroups);
        uris.Should().Contain(IdentityEndpoints.Events);
        uris.Should().Contain(IdentityEndpoints.ManageConsents);
        uris.Should().Contain(IdentityEndpoints.Logout);
        uris.Should().Contain(IdentityEndpoints.ManageSessions);
        uris.Should().Contain(IdentityEndpoints.MeSessions);
        uris.Should().Contain(IdentityEndpoints.MeProfile);
        uris.Should().Contain(IdentityEndpoints.MePassword);
        uris.Should().Contain(IdentityEndpoints.MeMfa);
        uris.Should().Contain(IdentityEndpoints.MeConsents);
        uris.Should().Contain(IdentityEndpoints.ManageClaimMappers);
        uris.Should().Contain(IdentityEndpoints.ManageClaimScopes);
        uris.Should().Contain(IdentityEndpoints.MeFederatedIdentities);
        uris.Should().Contain(IdentityEndpoints.ManageFederationProviders);
    }

    [Theory]
    [InlineData("identity-token", "direct-vm://identity-token")]
    [InlineData("identity-authorize", "direct-vm://identity-authorize")]
    [InlineData("identity-userinfo", "direct-vm://identity-userinfo")]
    [InlineData("identity-introspect", "direct-vm://identity-introspect")]
    [InlineData("identity-revoke", "direct-vm://identity-revoke")]
    [InlineData("identity-discovery", "direct-vm://identity-discovery")]
    [InlineData("identity-jwks", "direct-vm://identity-jwks")]
    [InlineData("identity-manage-apps", "direct-vm://identity-manage-apps")]
    [InlineData("identity-manage-scopes", "direct-vm://identity-manage-scopes")]
    [InlineData("identity-manage-users", "direct-vm://identity-manage-users")]
    [InlineData("identity-manage-tokens", "direct-vm://identity-manage-tokens")]
    [InlineData("identity-manage-groups", "direct-vm://identity-manage-groups")]
    [InlineData("identity-events", "direct-vm://identity-events")]
    [InlineData("identity-manage-consents", "direct-vm://identity-manage-consents")]
    [InlineData("identity-logout", "direct-vm://identity-logout")]
    [InlineData("identity-manage-sessions", "direct-vm://identity-manage-sessions")]
    [InlineData("identity-me-sessions", "direct-vm://identity-me-sessions")]
    [InlineData("identity-me-profile", "direct-vm://identity-me-profile")]
    [InlineData("identity-me-password", "direct-vm://identity-me-password")]
    [InlineData("identity-me-mfa", "direct-vm://identity-me-mfa")]
    [InlineData("identity-me-consents", "direct-vm://identity-me-consents")]
    [InlineData("identity-manage-claim-mappers", "direct-vm://identity-manage-claim-mappers")]
    [InlineData("identity-manage-claim-scopes", "direct-vm://identity-manage-claim-scopes")]
    [InlineData("identity-me-federated-identities", "direct-vm://identity-me-federated-identities")]
    [InlineData("identity-manage-federation-providers", "direct-vm://identity-manage-federation-providers")]
    public void Route_HasCorrectIdAndUri(string expectedRouteId, string expectedUri)
    {
        var route = _builder.Definitions
            .FirstOrDefault(d => d.GetRouteId() == expectedRouteId);

        route.Should().NotBeNull($"route with id '{expectedRouteId}' should exist");
        route!.GetFromUri().Should().Be(expectedUri);
    }

    [Fact]
    public void AllRoutes_Count_With_WebAuthn_Enabled_Is_48()
    {
        // Default builder above has WebAuthn.Enabled = false (49 routes — see
        // AllRoutes_Count_Is_45 for the breakdown). With WebAuthn toggled on the
        // conditional block in IdentityCoreRouteBuilder adds 3 more: identity-me-webauthn
        // (self-service), identity-mfa-webauthn (assertion login),
        // identity-mfa-webauthn-challenge-cleanup (timer). Total → 49 + 3 = 52.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(Substitute.For<IRedbService>());
        var opts = new RedbIdentityOptions();
        opts.WebAuthn.Enabled = true;
        opts.WebAuthn.RpId = "auth.test.local";
        opts.WebAuthn.Origins.Add("https://auth.test.local");
        services.AddSingleton(Options.Create(opts));

        services.AddDataProtection().UseEphemeralDataProtectionProvider();
        services.AddSingleton<MfaStateProtector>();
        services.AddSingleton<MfaSetupTokenProtector>();
        services.AddSingleton<MfaSecretProtector>();

        services.AddOpenIddict()
            .AddServer(o =>
            {
                o.EnableDegradedMode();
                o.SetIssuer(new Uri("https://identity.test.local/"));
                o.SetTokenEndpointUris("/connect/token");
                o.AllowClientCredentialsFlow();
                o.AddEphemeralEncryptionKey();
                o.AddEphemeralSigningKey();
                o.DisableAccessTokenEncryption();
                o.UseRedbRoute();
                o.AddEventHandler<ValidateTokenRequestContext>(b =>
                    b.UseInlineHandler(_ => default).SetOrder(int.MaxValue - 100_000).Build());
            });

        var sp = services.BuildServiceProvider();
        var builder = new IdentityCoreRouteBuilder(sp, sp.GetRequiredService<IOptions<RedbIdentityOptions>>());
        ((IRouteBuilder)builder).Configure(null!);

        builder.Definitions.Should().HaveCount(52);
        var ids = builder.Definitions.Select(d => d.GetRouteId()).ToList();
        ids.Should().Contain("identity-me-webauthn");
        ids.Should().Contain("identity-mfa-webauthn");
        ids.Should().Contain("identity-mfa-webauthn-challenge-cleanup");
    }

    [Fact]
    public void AllRoutes_Count_With_Par_Enabled_Is_44()
    {
        // Default builder above has EnablePushedAuthorization = false (46 routes — see
        // AllRoutes_Count_Is_45 for the breakdown, incl. the N7-3 admin impersonation overlay).
        // With PAR toggled on the conditional block in IdentityCoreRouteBuilder
        // adds exactly one route: identity-par.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(Substitute.For<IRedbService>());
        var opts = new RedbIdentityOptions { Features = new IdentityFeatureFlags { EnablePushedAuthorization = true } };
        services.AddSingleton(Options.Create(opts));

        services.AddDataProtection().UseEphemeralDataProtectionProvider();
        services.AddSingleton<MfaStateProtector>();
        services.AddSingleton<MfaSetupTokenProtector>();
        services.AddSingleton<MfaSecretProtector>();

        services.AddOpenIddict()
            .AddServer(o =>
            {
                o.EnableDegradedMode();
                o.SetIssuer(new Uri("https://identity.test.local/"));
                o.SetTokenEndpointUris("/connect/token");
                o.SetPushedAuthorizationEndpointUris("/connect/par");
                o.AllowClientCredentialsFlow();
                o.AddEphemeralEncryptionKey();
                o.AddEphemeralSigningKey();
                o.DisableAccessTokenEncryption();
                o.UseRedbRoute();
                o.AddEventHandler<ValidateTokenRequestContext>(b =>
                    b.UseInlineHandler(_ => default).SetOrder(int.MaxValue - 100_000).Build());
            });

        var sp = services.BuildServiceProvider();
        var builder = new IdentityCoreRouteBuilder(sp, sp.GetRequiredService<IOptions<RedbIdentityOptions>>());
        ((IRouteBuilder)builder).Configure(null!);

        // Default 49 + 1 PAR route = 50.
        builder.Definitions.Should().HaveCount(50);
        var ids = builder.Definitions.Select(d => d.GetRouteId()).ToList();
        ids.Should().Contain("identity-par");
    }

    [Fact]
    public void AllRoutes_With_ScimBulk_Enabled_RegistersBulkRoute()
    {
        // SCIM is opt-in; bulk is an additional opt-in on top of SCIM. Default builder
        // above has both off (46 routes — see AllRoutes_Count_Is_45 for the breakdown).
        // Enabling EnableScim adds /Users + /Groups (2 routes); EnableScimBulk adds the
        // bulk dispatcher (1 route) → 46 + 3 = 49.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(Substitute.For<IRedbService>());
        var opts = new RedbIdentityOptions
        {
            Features = new IdentityFeatureFlags { EnableScim = true, EnableScimBulk = true }
        };
        services.AddSingleton(Options.Create(opts));

        services.AddDataProtection().UseEphemeralDataProtectionProvider();
        services.AddSingleton<MfaStateProtector>();
        services.AddSingleton<MfaSetupTokenProtector>();
        services.AddSingleton<MfaSecretProtector>();

        services.AddOpenIddict()
            .AddServer(o =>
            {
                o.EnableDegradedMode();
                o.SetIssuer(new Uri("https://identity.test.local/"));
                o.SetTokenEndpointUris("/connect/token");
                o.AllowClientCredentialsFlow();
                o.AddEphemeralEncryptionKey();
                o.AddEphemeralSigningKey();
                o.DisableAccessTokenEncryption();
                o.UseRedbRoute();
                o.AddEventHandler<ValidateTokenRequestContext>(b =>
                    b.UseInlineHandler(_ => default).SetOrder(int.MaxValue - 100_000).Build());
            });

        var sp = services.BuildServiceProvider();
        var builder = new IdentityCoreRouteBuilder(sp, sp.GetRequiredService<IOptions<RedbIdentityOptions>>());
        ((IRouteBuilder)builder).Configure(null!);

        // Default 49 + 2 SCIM (Users + Groups) + 1 SCIM Bulk = 52.
        builder.Definitions.Should().HaveCount(52);
        var ids = builder.Definitions.Select(d => d.GetRouteId()).ToList();
        ids.Should().Contain(IdentityEndpoints.RouteIds.ScimUsers);
        ids.Should().Contain(IdentityEndpoints.RouteIds.ScimGroups);
        ids.Should().Contain(IdentityEndpoints.RouteIds.ScimBulk);
    }

    [Fact]
    public void AllRoutes_With_Scim_Enabled_But_Bulk_Disabled_OmitsBulkRoute()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(Substitute.For<IRedbService>());
        var opts = new RedbIdentityOptions
        {
            Features = new IdentityFeatureFlags { EnableScim = true, EnableScimBulk = false }
        };
        services.AddSingleton(Options.Create(opts));

        services.AddDataProtection().UseEphemeralDataProtectionProvider();
        services.AddSingleton<MfaStateProtector>();
        services.AddSingleton<MfaSetupTokenProtector>();
        services.AddSingleton<MfaSecretProtector>();

        services.AddOpenIddict()
            .AddServer(o =>
            {
                o.EnableDegradedMode();
                o.SetIssuer(new Uri("https://identity.test.local/"));
                o.SetTokenEndpointUris("/connect/token");
                o.AllowClientCredentialsFlow();
                o.AddEphemeralEncryptionKey();
                o.AddEphemeralSigningKey();
                o.DisableAccessTokenEncryption();
                o.UseRedbRoute();
                o.AddEventHandler<ValidateTokenRequestContext>(b =>
                    b.UseInlineHandler(_ => default).SetOrder(int.MaxValue - 100_000).Build());
            });

        var sp = services.BuildServiceProvider();
        var builder = new IdentityCoreRouteBuilder(sp, sp.GetRequiredService<IOptions<RedbIdentityOptions>>());
        ((IRouteBuilder)builder).Configure(null!);

        // Default 49 + 2 SCIM (Users + Groups), bulk omitted = 51.
        builder.Definitions.Should().HaveCount(51);
        var ids = builder.Definitions.Select(d => d.GetRouteId()).ToList();
        ids.Should().NotContain(IdentityEndpoints.RouteIds.ScimBulk);
    }
}
