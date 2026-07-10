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
using redb.Identity.Contracts.Configuration;
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
using redb.Identity.Core.Routes;

namespace redb.Identity.Tests.Infrastructure;

/// <summary>
/// Integration fixture using the PRODUCTION DI bootstrap (<see cref="RedbIdentityServiceExtensions.AddRedbIdentityServer"/>).
/// Real PostgreSQL + real OpenIddict stores (no degraded mode, no mocks).
/// Provides <see cref="ProducerTemplate"/> for direct-vm:// access.
/// Creates a test client + test user in the database on startup.
/// </summary>
public sealed class ProductionBootstrapFixture : IAsyncLifetime
{
    private ServiceProvider _sp = null!;
    private RouteContext _ctx = null!;

    public const string TestClientId = "integration-test-client";
    public const string TestClientSecret = "integration-test-secret-value";
    public const string TestClientIdPublic = "integration-test-pkce-client";
    public const string TestUsername = "testuser";
    public const string TestPassword = "Test@Password123";
    public const string TestRedirectUri = "http://localhost/callback";

    public ProducerTemplate Producer { get; private set; } = null!;

    /// <summary>
    /// Captive root-scoped <see cref="IRedbService"/>. <b>NOT thread-safe across
    /// concurrent calls</b> — the underlying <see cref="System.Data.Common.DbConnection"/>
    /// (Npgsql / Microsoft.Data.SqlClient) cannot multiplex commands. Reusing this
    /// instance from a test thread that also triggers Worker-side route processing
    /// (which fires its own DB writes through the same root-scoped service when
    /// resolved from <c>_sp</c>) produces:
    /// <list type="bullet">
    ///   <item>PG: <c>NpgsqlOperationInProgressException : A command is already in progress</c></item>
    ///   <item>SQL Server: <c>SqlConnection does not support parallel transactions</c></item>
    ///   <item>SQLite: <c>SqliteException(SQLITE_BUSY)</c></item>
    /// </list>
    /// Use <see cref="WithRedb{T}"/> / <see cref="WithRedb"/> instead from any test
    /// path that runs concurrently with the Worker (any test that goes through the
    /// HTTP/direct-vm pipeline). The captive <see cref="Redb"/> property is retained
    /// for setup code that runs before the Worker is processing requests
    /// (<see cref="InitializeAsync"/>, <c>SyncSchemeAsync</c> bootstrap, etc.) where
    /// the lack of concurrent access makes the captive resolution safe.
    /// </summary>
    public IRedbService Redb { get; private set; } = null!;

    /// <summary>
    /// Run <paramref name="action"/> against a <b>fresh, scoped</b>
    /// <see cref="IRedbService"/>. Each call opens a brand-new
    /// <see cref="IServiceScope"/>, resolves a per-scope IRedbService (which in
    /// turn lazily opens its own provider connection on first use), runs the
    /// action, and disposes the scope on return — so no <see cref="System.Data.Common.DbConnection"/>
    /// is shared with any concurrent caller.
    /// </summary>
    public async Task<T> WithRedb<T>(Func<IRedbService, Task<T>> action)
    {
        if (action is null) throw new ArgumentNullException(nameof(action));
        using var scope = _sp.CreateScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        return await action(redb).ConfigureAwait(false);
    }

    /// <summary>
    /// Void-result overload of <see cref="WithRedb{T}"/>.
    /// </summary>
    public async Task WithRedb(Func<IRedbService, Task> action)
    {
        if (action is null) throw new ArgumentNullException(nameof(action));
        using var scope = _sp.CreateScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        await action(redb).ConfigureAwait(false);
    }

    public IServiceProvider ServiceProvider => _sp;
    public long TestUserId { get; private set; }
    /// <summary>
    /// The public per-user GUID (UserProps.value_guid) that surfaces in every
    /// JWT as the <c>sub</c> claim. Tests asserting on <c>sub</c> should compare
    /// against this — never against <see cref="TestUserId"/>, which is the
    /// internal bigint mirrored into the <c>redb:user_id</c> claim.
    /// </summary>
    public Guid TestSubjectGuid { get; private set; }

    /// <summary>
    /// Shared fake external provider registered in DI. Tests configure handlers
    /// before each ROPC call. Empty handlers → returns null (skip) → no impact on other tests.
    /// </summary>
    public FakeExternalUserProvider FakeExternalProvider { get; } = new();

    public async Task InitializeAsync()
    {
        var config = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json")
            .Build();

        var cs = config.GetConnectionString("Postgres")
                 ?? throw new InvalidOperationException("ConnectionStrings:Postgres not found");

        var services = new ServiceCollection();
        services.AddLogging(b => b
            .SetMinimumLevel(LogLevel.Warning));

        // Real PostgreSQL + Pro with DeleteInsert
        services.AddRedbForTests(cs);

        // SharedVmRegistry (required for direct-vm)
        services.AddSingleton<SharedVmRegistry>();

        // Identity options
        var identityOptions = new RedbIdentityOptions
        {
            TokenRetentionDays = 30,
            TokenThrottleMaxPerPeriod = 1000,
            TokenThrottlePeriod = TimeSpan.FromSeconds(1),
            Issuer = new Uri("https://identity.test.local/"),
            AllowEphemeralKeys = true,
            DisableAccessTokenEncryption = true,
            Features = new IdentityFeatureFlags { EnableDeviceCodeFlow = true },
            EnablePasswordFlow = true,
            EnableTokenExchange = true
        };
        services.AddSingleton(Options.Create(identityOptions));

        // Register fake external provider BEFORE identity server bootstrap.
        // Empty handlers = skip all users = no impact on existing tests.
        services.AddSingleton<IExternalUserProvider>(FakeExternalProvider);

        // PRODUCTION bootstrap — the whole point of this fixture
        services.AddRedbIdentityServer(identityOptions);

        // E7: ValidateOnBuild detects captive dependencies (Singleton ctor depending on
        // Scoped) at build time — the cardinal anti-pattern Sprint E7 targets. We do NOT
        // turn ValidateScopes on here because this fixture intentionally resolves scoped
        // services via the root provider (long-standing test-bed convention; routing all
        // tests through per-scope resolution would touch dozens of files and is unrelated
        // to the captive-dep audit).
        _sp = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateScopes = false,
            ValidateOnBuild = true,
        });

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
        await Redb.SyncSchemeAsync<UserProps>();
        await Redb.SyncSchemeAsync<DataProtectionKeyProps>();
        await Redb.SyncSchemeAsync<SessionProps>();
        await Redb.SyncSchemeAsync<MfaProps>();
        await Redb.SyncSchemeAsync<GroupProps>();
        await Redb.SyncSchemeAsync<GroupMemberProps>();
        await Redb.InitializeTypeRegistryAsync();

        // Fix btree index overflow for large Payload values (4+ scope tokens)
        await IndexFixHelper.FixValueStringIndexAsync(cs);

        // Seed test data
        await SeedTestClient();
        await SeedTestUser();

        // Create RouteContext
        _ctx = new RouteContext(_sp, "production-bootstrap-integration");

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

        // Delete stale test apps (may have wrong secret format from prior runs)
        var existingConfidential = await manager.FindByClientIdAsync(TestClientId);
        if (existingConfidential is not null)
            await manager.DeleteAsync(existingConfidential);

        var existingPublic = await manager.FindByClientIdAsync(TestClientIdPublic);
        if (existingPublic is not null)
            await manager.DeleteAsync(existingPublic);

        // Confidential client — manager will BCrypt-hash the secret properly
        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = TestClientId,
            ClientSecret = TestClientSecret,
            ClientType = OpenIddictConstants.ClientTypes.Confidential,
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
            DisplayName = "Integration Test Client",
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Introspection,
                OpenIddictConstants.Permissions.Endpoints.Revocation,
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                OpenIddictConstants.Permissions.GrantTypes.Password,
                "gt:urn:ietf:params:oauth:grant-type:token-exchange",
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Phone,
                OpenIddictConstants.Permissions.Scopes.Address,
                OpenIddictConstants.Permissions.Prefixes.Scope + "openid",
                OpenIddictConstants.Permissions.Prefixes.Scope + "offline_access",
                OpenIddictConstants.Permissions.Prefixes.Scope + "groups",
                OpenIddictConstants.Permissions.Prefixes.Scope + "roles",
                OpenIddictConstants.Permissions.ResponseTypes.Code
            },
            RedirectUris = { new Uri(TestRedirectUri) },
            Requirements = { OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange }
        });

        // Public PKCE client — no secret
        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = TestClientIdPublic,
            ClientType = OpenIddictConstants.ClientTypes.Public,
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
            DisplayName = "Integration Test PKCE Client",
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Revocation,
                OpenIddictConstants.Permissions.Endpoints.DeviceAuthorization,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                OpenIddictConstants.Permissions.GrantTypes.DeviceCode,
                OpenIddictConstants.Permissions.Prefixes.Scope + "openid",
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Phone,
                OpenIddictConstants.Permissions.Scopes.Address,
                OpenIddictConstants.Permissions.Prefixes.Scope + "offline_access",
                OpenIddictConstants.Permissions.Prefixes.Scope + "groups",
                OpenIddictConstants.Permissions.Prefixes.Scope + "roles",
                OpenIddictConstants.Permissions.ResponseTypes.Code
            },
            RedirectUris = { new Uri(TestRedirectUri) },
            Requirements = { OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange }
        });
    }

    private async Task SeedTestUser()
    {
        // Try to find existing user in _users table
        var coreUser = await Redb.UserProvider.GetUserByLoginAsync(TestUsername);

        if (coreUser is null)
        {
            // Create user in _users table
            coreUser = await Redb.UserProvider.CreateUserAsync(new redb.Core.Models.Users.CreateUserRequest
            {
                Login = TestUsername,
                Password = TestPassword,
                Name = TestUsername,
                Email = "testuser@example.com",
                Phone = "+1234567890",
                Enabled = true
            });
        }
        TestUserId = coreUser.Id;

        // Ensure OIDC profile extension exists (linked via key = _users._id)
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
        else if (oidcObj.value_guid is null || oidcObj.value_guid == Guid.Empty)
        {
            // First test run after migration may find a row without value_guid — backfill it.
            oidcObj.value_guid = Guid.NewGuid();
        }
        TestSubjectGuid = oidcObj.value_guid!.Value;
        oidcObj.Props.EmailVerified = true;
        oidcObj.Props.GivenName = "Test";
        oidcObj.Props.FamilyName = "User";
        oidcObj.Props.PhoneNumberVerified = false;
        oidcObj.Props.Address = new AddressClaim
        {
            StreetAddress = "123 Test Street",
            Locality = "Testville",
            Region = "TS",
            PostalCode = "12345",
            Country = "US"
        };
        oidcObj.Props.CustomClaims = new Dictionary<string, string>
        {
            ["department"] = "Engineering",
            ["employee_id"] = "EMP-0042"
        };
        await Redb.SaveAsync(oidcObj);
    }

    public async Task<object?> Request(string endpointUri, object body)
    {
        return await Producer.RequestBody(endpointUri, body);
    }

    /// <summary>
    /// Sends an authorize request with the test user's session pre-attached.
    /// Creates a session record (simulating login) and sets session_id header.
    /// </summary>
    public async Task<object?> RequestWithSession(string endpointUri, object body)
    {
        // Create a session record (simulates what LoginProcessor does at login time).
        // Goes through WithRedb so SessionService.CreateAsync owns a fresh NpgsqlConnection
        // for the BeginTransaction → SaveAsync chain — captive _fx.Redb is racy here
        // because callers (e.g. SessionIntegrationTests.ManageSessions_RevokeAll_*) chain
        // multiple Authorize() calls back-to-back; the previous call's WireTap audit
        // pipeline can still be flushing INSERTs onto the captive connection when the
        // next call's SessionService.CreateAsync arrives, surfacing as
        // "InvalidOperationException : Connection is busy" at BeginTransactionAsync.
        var session = await WithRedb(async redb =>
        {
            var sessionService = new SessionService(redb);
            return await sessionService.CreateAsync(TestUserId, applicationObjectId: 0);
        });

        var headers = new Dictionary<string, object?>
        {
            ["session_user_id"] = TestUserId,
            ["session_username"] = TestUsername,
            ["session_id"] = session.id
        };
        var exchange = await RequestWithHeaders(endpointUri, body, headers);
        return exchange.HasOut ? exchange.Out!.Body : exchange.In.Body;
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
        // Pure test-side adaptor; runtime contract (Out ?? In) is unchanged.
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

[CollectionDefinition("ProductionBootstrap")]
public class ProductionBootstrapCollection : ICollectionFixture<ProductionBootstrapFixture>;
