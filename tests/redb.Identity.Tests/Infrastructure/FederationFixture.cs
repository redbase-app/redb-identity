using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using redb.Core;
using redb.Core.Models.Configuration;
using redb.Core.Extensions;
using redb.Core.Pro.Extensions;
using redb.Core.Models.Entities;
using redb.Core.Query;
using redb.Identity.Core;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.DataProtection;
using redb.Identity.Core.OpenIddict;
using redb.Identity.Contracts.Routes;
using redb.Identity.Core.Services;
using redb.Postgres.Pro.Extensions;
using redb.Route.Abstractions;
using redb.Route.Components;
using redb.Route.Core;
using Xunit;
using redb.Identity.Contracts.Configuration;
using redb.Identity.Core.Routes;

namespace redb.Identity.Tests.Infrastructure;

/// <summary>
/// Integration fixture for federation (OIDC redirect-based auth) tests.
/// Real PostgreSQL + production DI + federation enabled with <see cref="FakeFederatedAuthProvider"/>.
/// </summary>
public sealed class FederationFixture : IAsyncLifetime
{
    private ServiceProvider _sp = null!;
    private RouteContext _ctx = null!;

    public const string TestClientId = "federation-test-client";
    public const string TestClientSecret = "federation-test-secret-value";
    public const string TestUsername = "fed-testuser";
    public const string TestPassword = "FedTest@Password123";
    public const string TestRedirectUri = "http://localhost/callback";

    public ProducerTemplate Producer { get; private set; } = null!;
    public IRedbService Redb { get; private set; } = null!;
    public IServiceProvider ServiceProvider => _sp;
    public long TestUserId { get; private set; }
    public FakeFederatedAuthProvider FakeProvider { get; } = new();

    public async Task InitializeAsync()
    {
        var config = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json")
            .Build();

        var cs = config.GetConnectionString("Postgres")
                 ?? throw new InvalidOperationException("ConnectionStrings:Postgres not found");

        var services = new ServiceCollection();
        services.AddLogging(b => b.SetMinimumLevel(LogLevel.Warning));

        services.AddRedbForTests(cs);

        services.AddSingleton<SharedVmRegistry>();

        var identityOptions = new RedbIdentityOptions
        {
            TokenRetentionDays = 30,
            TokenThrottleMaxPerPeriod = 1000,
            TokenThrottlePeriod = TimeSpan.FromSeconds(1),
            Issuer = new Uri("https://identity.test.local/"),
            AllowEphemeralKeys = true,
            DisableAccessTokenEncryption = true,
            EnablePasswordFlow = true,
            Features = new IdentityFeatureFlags { EnableFederation = true },
            FederationProviders =
            [
                // Dummy config entry to satisfy the FederationProviders.Count > 0 guard
                // The actual IFederatedAuthProvider used in tests is FakeProvider below
                new FederationProviderConfig
                {
                    ProviderId = "config-oidc-unused",
                    DisplayName = "Unused Config OIDC",
                    Authority = "http://localhost:19999",
                    ClientId = "unused",
                    ClientSecret = "unused"
                }
            ]
        };
        services.AddSingleton(Options.Create(identityOptions));

        // Register the fake federated auth provider (used by tests via ProviderId = "fake-oidc")
        services.AddSingleton<IFederatedAuthProvider>(FakeProvider);

        services.AddRedbIdentityServer(identityOptions);

        _sp = services.BuildServiceProvider();

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
        await Redb.SyncSchemeAsync<UserProps>();
        await Redb.SyncSchemeAsync<DataProtectionKeyProps>();
        await Redb.SyncSchemeAsync<SessionProps>();
        await Redb.SyncSchemeAsync<MfaProps>();
        await Redb.SyncSchemeAsync<GroupProps>();
        await Redb.SyncSchemeAsync<GroupMemberProps>();
        await Redb.InitializeTypeRegistryAsync();

        await IndexFixHelper.FixValueStringIndexAsync(cs);

        await SeedTestClient();
        await SeedTestUser();

        _ctx = new RouteContext(_sp, "federation-integration");
        _ctx.AddRoutes(new IdentityCoreRouteBuilder(_sp, Options.Create(identityOptions)));
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

    private async Task SeedTestClient()
    {
        var manager = _sp.GetRequiredService<IOpenIddictApplicationManager>();

        var existing = await manager.FindByClientIdAsync(TestClientId);
        if (existing is not null)
            await manager.DeleteAsync(existing);

        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = TestClientId,
            ClientSecret = TestClientSecret,
            ClientType = OpenIddictConstants.ClientTypes.Confidential,
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
            DisplayName = "Federation Test Client",
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.Password,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Prefixes.Scope + "openid",
                OpenIddictConstants.Permissions.ResponseTypes.Code
            },
            RedirectUris = { new Uri(TestRedirectUri) },
            Requirements = { OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange }
        });
    }

    private async Task SeedTestUser()
    {
        var coreUser = await Redb.UserProvider.GetUserByLoginAsync(TestUsername);

        if (coreUser is null)
        {
            coreUser = await Redb.UserProvider.CreateUserAsync(new redb.Core.Models.Users.CreateUserRequest
            {
                Login = TestUsername,
                Password = TestPassword,
                Name = TestUsername,
                Email = "fed-testuser@example.com",
                Enabled = true
            });
        }
        TestUserId = coreUser.Id;

        var oidcObj = await Redb.Query<UserProps>()
            .WhereRedb(o => o.Key == coreUser.Id)
            .FirstOrDefaultAsync();

        if (oidcObj is null)
        {
            oidcObj = new RedbObject<UserProps>(new UserProps());
            oidcObj.name = TestUsername;
            oidcObj.key = coreUser.Id;
            oidcObj.value_guid = Guid.NewGuid();
        }
        oidcObj.Props.EmailVerified = true;
        oidcObj.Props.GivenName = "Fed";
        oidcObj.Props.FamilyName = "TestUser";
        await Redb.SaveAsync(oidcObj);
    }

    public async Task<object?> Request(string endpointUri, object body)
    {
        return await Producer.RequestBody(endpointUri, body);
    }

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

[CollectionDefinition("Federation")]
public class FederationCollection : ICollectionFixture<FederationFixture>;
