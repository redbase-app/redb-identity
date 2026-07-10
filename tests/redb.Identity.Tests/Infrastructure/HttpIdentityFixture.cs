using System.Net;
using System.Net.Sockets;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Validation;
using redb.Core;
using redb.Core.Extensions;
using redb.Core.Pro.Extensions;
using redb.Core.Models.Configuration;
using redb.Core.Extensions;
using redb.Core.Pro.Extensions;
using redb.Identity.Core;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.DataProtection;
using redb.Identity.Core.OpenIddict;
using redb.Identity.Contracts.Routes;
using redb.Identity.Core.Routes.Processors;
using redb.Identity.Core.Services;
using redb.Identity.Http.Security;
using redb.Identity.Http;
using redb.Postgres.Pro.Extensions;
using redb.Route.Abstractions;
using redb.Route.Components;
using redb.Route.Core;
using redb.Route.Http;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using redb.Identity.Core.Routes;

namespace redb.Identity.Tests.Infrastructure;

/// <summary>
/// Full integration fixture: real PostgreSQL + RouteContext with Core + HTTP facade routes
/// + Kestrel on a random port. Provides both <see cref="HttpClient"/> for HTTP E2E
/// and <see cref="ProducerTemplate"/> for direct-vm:// access.
/// </summary>
public sealed class HttpIdentityFixture : IAsyncLifetime
{
    private ServiceProvider _sp = null!;
    private RouteContext _ctx = null!;

    public int Port { get; private set; }
    public string BaseUrl => $"http://localhost:{Port}";
    public HttpClient Http { get; private set; } = null!;
    public ProducerTemplate Producer { get; private set; } = null!;
    public IRedbService Redb { get; private set; } = null!;
    public IServiceProvider ServiceProvider => _sp;

    /// <summary>
    /// Bearer token with <c>identity:manage</c> scope issued during fixture setup.
    /// Use via <c>Authorization: Bearer {ManagementToken}</c>.
    /// </summary>
    public string ManagementToken { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        Port = GetFreePort();

        var config = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json")
            .Build();

        var cs = config.GetConnectionString("Postgres")
            ?? throw new InvalidOperationException("ConnectionStrings:Postgres not found");

        var services = new ServiceCollection();
        services.AddLogging(b => b.SetMinimumLevel(LogLevel.Warning));

        // Real PostgreSQL-backed IRedbService (free or Pro per REDB_USE_PRO env)
        services.AddRedbForTests(cs);

        // SharedVmRegistry (required for direct-vm)
        services.AddSingleton<SharedVmRegistry>();

        // DataProtection (needed for session cookies)
        services.AddDataProtection().UseEphemeralDataProtectionProvider();

        // MFA protectors — required by IdentityCoreRouteBuilder.Configure() (line 175)
        // even when no MFA tests run. Lightweight; pulls only IDataProtectionProvider.
        services.AddSingleton<MfaStateProtector>();
        services.AddSingleton<MfaSetupTokenProtector>();
        services.AddSingleton<MfaSecretProtector>();

        // Identity options
        var identityOptions = new RedbIdentityOptions
        {
            TokenRetentionDays = 30,
            TokenThrottleMaxPerPeriod = 1000,
            TokenThrottlePeriod = TimeSpan.FromSeconds(1),
            AllowEphemeralKeys = true
        };
        services.AddSingleton(Options.Create(identityOptions));

        // Transport options with the test port
        var transportOptions = new IdentityTransportOptions();
        transportOptions.Http.PublicPort = Port;
        transportOptions.Http.CorsEnabled = true;
        // Use AdditionalAllowedOrigins (the new CSV slot) so the per-request resolver
        // matches and echoes a single origin verbatim. The deprecated CorsOrigins still
        // works (it is folded into AdditionalAllowedOrigins) but new tests should use
        // the modern slot.
        transportOptions.Http.AdditionalAllowedOrigins = "http://localhost:3000,http://localhost:5173";
        services.AddSingleton(Options.Create(transportOptions));

        // OpenIddict in degraded mode
        services.AddOpenIddict()
            .AddCore(core => core.UseRedbStores())
            .AddServer(options =>
            {
                options.EnableDegradedMode();
                options.SetIssuer(new Uri($"http://localhost:{Port}/"));

                options.SetTokenEndpointUris("/connect/token");
                options.SetAuthorizationEndpointUris("/connect/authorize");
                options.SetIntrospectionEndpointUris("/connect/introspect");
                options.SetRevocationEndpointUris("/connect/revoke");
                options.SetConfigurationEndpointUris("/.well-known/openid-configuration");

                options.AllowClientCredentialsFlow();
                options.AllowAuthorizationCodeFlow();
                options.AllowRefreshTokenFlow();

                options.RegisterScopes(
                    Scopes.OpenId, Scopes.Profile, Scopes.Email,
                    Scopes.OfflineAccess, identityOptions.ManagementScope);

                options.AddEphemeralEncryptionKey();
                options.AddEphemeralSigningKey();
                options.DisableAccessTokenEncryption();

                options.UseRedbRoute();

                // Degraded mode: skip validation
                options.AddEventHandler<ValidateTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context => default)
                        .SetOrder(int.MaxValue - 100_000).Build());

                options.AddEventHandler<ValidateAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(context => default)
                        .SetOrder(int.MaxValue - 100_000).Build());

                options.AddEventHandler<ValidateIntrospectionRequestContext>(builder =>
                    builder.UseInlineHandler(context => default)
                        .SetOrder(int.MaxValue - 100_000).Build());

                options.AddEventHandler<ValidateRevocationRequestContext>(builder =>
                    builder.UseInlineHandler(context => default)
                        .SetOrder(int.MaxValue - 100_000).Build());

                // Provide ClaimsPrincipal for client_credentials
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
                        })
                        .SetOrder(OpenIddictServerHandlers.Exchange.AttachPrincipal
                            .Descriptor.Order + 100).Build());
            })
            .AddValidation(validation =>
            {
                validation.UseLocalServer();
                validation.UseDataProtection();

                // Custom handler: inject bearer token for programmatic validation
                validation.AddEventHandler<OpenIddictValidationEvents.ProcessAuthenticationContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        if (context.Transaction.Properties.TryGetValue(
                                ManagementBearerAuthProcessor.TokenPropertyKey, out var rawToken)
                            && rawToken is string token)
                        {
                            context.AccessToken = token;
                            context.ExtractAccessToken = false;
                        }

                        return default;
                    })
                    .SetOrder(int.MinValue + 500)
                    .Build());
            });

        _sp = services.BuildServiceProvider();

        // Initialize PostgreSQL schema
        Redb = _sp.GetRequiredService<IRedbService>();
        try { await Redb.InitializeAsync(ensureCreated: true); }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"InitializeAsync(ensureCreated:true) failed, falling back: {ex.GetType().Name}: {ex.Message}");
            await Redb.InitializeAsync();
        }

        await Redb.SyncSchemeAsync<ApplicationProps>();
        await Redb.SyncSchemeAsync<AuthorizationProps>();
        await Redb.SyncSchemeAsync<ScopeProps>();
        await Redb.SyncSchemeAsync<TokenProps>();
        await Redb.SyncSchemeAsync<DataProtectionKeyProps>();
        await Redb.InitializeTypeRegistryAsync();

        // Create RouteContext
        _ctx = new RouteContext(_sp, "identity-http-integration");

        // Register HTTP component
        _ctx.AddComponent(new HttpComponent
        {
            ServerManager = new SharedHttpServerManager()
        });

        // Bearer auth processors live in Core's RouteBuilder so they get exposed as
        // `direct-vm://identity-auth-{management,scim}` consumers; the HTTP facade
        // calls them inline via .To(...).
        var validationFactory = _sp.GetRequiredService<IOpenIddictValidationFactory>();
        var validationDispatcher = _sp.GetRequiredService<IOpenIddictValidationDispatcher>();
        var managementAuth = new ManagementBearerAuthProcessor(
            validationFactory, validationDispatcher,
            new[] { identityOptions.ManagementScope, identityOptions.AccountScope },
            anonymousPathPrefixes: new[] { "/api/v1/identity/password/", "/api/v1/identity/account/" });

        IProcessor? scimAuth = identityOptions.Features.EnableScim
            ? new ManagementBearerAuthProcessor(validationFactory, validationDispatcher, identityOptions.ScimScope)
            : null;

        // Register all 13 identity core routes
        _ctx.AddRoutes(new IdentityCoreRouteBuilder(_sp, Options.Create(identityOptions),
            auditOptions: null,
            managementAuth: managementAuth,
            scimAuth: scimAuth));

        // Register HTTP facade routes (auth flows via direct-vm into Core)
        var ticketService = new SessionTicketService(
            _sp.GetRequiredService<IDataProtectionProvider>());
        _ctx.AddRoutes(new HttpFacadeRouteBuilder(
            ticketService,
            Options.Create(transportOptions)));

        await _ctx.Start();

        Producer = new ProducerTemplate(_ctx);
        Producer.Start();

        Http = new HttpClient { BaseAddress = new Uri(BaseUrl) };

        // Obtain a management bearer token for tests
        ManagementToken = await ObtainManagementTokenAsync();
    }

    public async Task DisposeAsync()
    {
        Http.Dispose();
        Producer.Stop();
        Producer.Dispose();
        await _ctx.DisposeAsync();
        await _sp.DisposeAsync();
    }

    /// <summary>
    /// Issues a management bearer token via the token endpoint (client_credentials + identity:manage scope).
    /// </summary>
    private async Task<string> ObtainManagementTokenAsync()
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "management-test-client",
            ["client_secret"] = "management-test-secret",
            ["scope"] = "identity:manage"
        });

        var response = await Http.PostAsync("/connect/token", content);
        if (!response.IsSuccessStatusCode)
        {
            var errorBody = await response.Content.ReadAsStringAsync();
            throw new InvalidOperationException(
                $"Token endpoint returned {response.StatusCode}: {errorBody}");
        }

        var json = await JsonSerializer.DeserializeAsync<JsonElement>(
            await response.Content.ReadAsStreamAsync());
        return json.GetProperty("access_token").GetString()
            ?? throw new InvalidOperationException("Token endpoint did not return access_token");
    }

    private static int GetFreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}

[CollectionDefinition("HttpIdentity")]
public class HttpIdentityCollection : ICollectionFixture<HttpIdentityFixture>;
