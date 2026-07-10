using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Validation;
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
using redb.Identity.Contracts.Configuration;
using redb.Identity.Contracts.Routes;
using redb.Identity.Core.Routes.Processors;
using Microsoft.AspNetCore.DataProtection;
using redb.Identity.Core.Services;
using redb.Identity.Http.Security;
using redb.Identity.Http;
using redb.Postgres.Pro.Extensions;
using redb.Route.Abstractions;
using redb.Route.Components;
using redb.Route.Core;
using redb.Route.Http;
using Xunit;
using redb.Identity.Core.Routes;

namespace redb.Identity.Tests.Infrastructure;

/// <summary>
/// Full-stack integration fixture: PRODUCTION OpenIddict (real stores, no degraded mode)
/// + real PostgreSQL + Kestrel HTTP on a random port.
/// Validates the complete path: HTTP → controller → route → OpenIddict pipeline → redb stores → PostgreSQL.
/// </summary>
public sealed class ProductionHttpFixture : IAsyncLifetime
{
    private ServiceProvider _sp = null!;
    private RouteContext _ctx = null!;

    public const string TestClientId = "e2e-confidential";
    public const string TestClientSecret = "e2e-secret-value-1234";
    public const string TestPublicClientId = "e2e-public-pkce";
    public const string TestMgmtClientId = "e2e-management";
    public const string TestMgmtSecret = "e2e-mgmt-secret-1234";
    public const string TestConsentClientId = "e2e-explicit-consent";
    public const string TestUsername = "e2e-user";
    public const string TestPassword = "E2E@Test123!";
    public const string TestRedirectUri = "http://localhost/callback";
    public const string DynamicRegAccessToken = "e2e-dynreg-initial-token-2026";

    // Scope-authorization fixtures: a gated scope ("identity:admin") and a group
    // ("identity-admins") that user-bound flows must belong to in order to obtain
    // the gated scope. Configured via RedbIdentityOptions.ScopeRequiredGroups.
    public const string AdminGatedScope = "identity:admin";
    public const string AdminGroupName = "identity-admins";
    public const string TestAdminUsername = "e2e-admin";
    public const string TestAdminPassword = "E2E@Admin123!";

    // B1 — bootstrap-admin emergency endpoint. Tests in BootstrapAdminTests
    // toggle this on the live options instance and clean state per test.
    public const string BootstrapSecret = "test-bootstrap-secret-XYZ-32-chars-long-aaa";
    // Bootstrap-suite isolated client_id. Was "identity-web" — same value as the
    // default SeedWebClientOptions.ClientId — and collided with anything in the
    // fixture lifetime that happened to seed "identity-web" (an earlier explicit
    // SeedWebClient run, a stale OpenIddict cache entry surviving a half-cleanup,
    // an unrelated test class that touched the same client). Even with the seed
    // turned off the collisions kept reappearing under the full-suite run because
    // they only required ONE stale entry across the entire xUnit fixture lifetime.
    // Using a unique value here removes the variable: nothing else in the codebase
    // refers to "bootstrap-admin-test-client", so the bootstrap tests own the
    // lifecycle of this client_id end-to-end.
    public const string BootstrapWebClientId = "bootstrap-admin-test-client";
    public const string BootstrapAdminScope = "identity:admin-bootstrap-test";
    public const string BootstrapAdminGroup = "identity-bootstrap-admins";

    public int Port { get; private set; }
    public string BaseUrl => $"http://localhost:{Port}";
    public HttpClient Http { get; private set; } = null!;

    /// <summary>
    /// N-4 (Session C): captures every transactional e-mail dispatched by the identity
    /// system. Tests use this to extract reset tokens and to assert that anti-enumeration
    /// gates correctly suppress delivery.
    /// </summary>
    public InMemoryEmailNotificationChannel Emails =>
        _sp.GetRequiredService<InMemoryEmailNotificationChannel>();
    public ProducerTemplate Producer { get; private set; } = null!;

    /// <summary>
    /// CAPTIVE — uses a single IRedbService resolved from the root provider, which means a
    /// single underlying NpgsqlConnection. Do NOT use from tests for ad-hoc reads/writes that
    /// can run in parallel with HTTP requests, OpenIddict pipeline work, or audit-sink fan-out
    /// — they will collide with "A command is already in progress" / "state 'Copy'".
    /// Use <see cref="UseRedbAsync"/> instead, which opens a fresh DI scope per call so each
    /// operation gets its own connection.
    /// <para>
    /// Kept here only because (a) initial seed / schema-sync runs strictly serial during
    /// <see cref="InitializeAsync"/>, and (b) some legacy tests still reach for it. New tests
    /// MUST go through <see cref="UseRedbAsync"/>.
    /// </para>
    /// </summary>
    /// <summary>
    /// Per-call scoped <see cref="IRedbService"/>. Each access opens a fresh DI scope from the
    /// fixture <see cref="IServiceProvider"/> so the resolved <see cref="IRedbService"/> uses its
    /// own <c>NpgsqlConnection</c> from the pool. Scopes are tracked in <see cref="_testScopes"/>
    /// and disposed during <see cref="DisposeAsync"/>. This keeps backwards compatibility with
    /// legacy tests that capture <c>_fx.Redb</c> into ad-hoc service objects (e.g. <c>new
    /// ConsentService(_fx.Redb)</c>) while removing the captive-singleton race that otherwise
    /// surfaces as <c>NpgsqlOperationInProgressException</c> ("command already in progress" /
    /// state 'Copy').
    /// <para>
    /// New tests SHOULD prefer <see cref="UseRedbAsync"/> when possible — it gives the scope a
    /// short, deterministic lifetime instead of leaking until fixture teardown.
    /// </para>
    /// <para>
    /// IMPORTANT: do NOT use this for explicit transactions — each access returns a different
    /// <see cref="IRedbService"/> instance bound to a different connection. Use
    /// <see cref="UseRedbAsync"/> with a single delegate for transactional work.
    /// </para>
    /// </summary>
    [Obsolete("Prefer UseRedbAsync(...) — _fx.Redb returns a single fixture-scoped IRedbService that shares one NpgsqlConnection; safe only for sequential test-side reads/writes.")]
    public IRedbService Redb
    {
        get
        {
            // Lazily create ONE long-lived DI scope and resolve a single IRedbService from it.
            // Previous implementation created a new scope per access and stashed it in a bag
            // that was only drained at fixture teardown — leaking one NpgsqlConnection per
            // access and exhausting the pool (200) within a single full-suite run.
            // Tests that need their own connection MUST use UseRedbAsync(...) which scopes
            // properly per delegate.
            if (_captiveRedb is not null) return _captiveRedb;
            lock (_captiveRedbLock)
            {
                if (_captiveRedb is null)
                {
                    _captiveScope = _sp.CreateAsyncScope();
                    _captiveRedb = _captiveScope.Value.ServiceProvider.GetRequiredService<IRedbService>();
                }
                return _captiveRedb;
            }
        }
    }

    private readonly object _captiveRedbLock = new();
    private AsyncServiceScope? _captiveScope;
    private IRedbService? _captiveRedb;

    public IServiceProvider ServiceProvider => _sp;

    /// <summary>
    /// Opens a fresh DI scope, resolves a per-scope <see cref="IRedbService"/> (and therefore a
    /// fresh <c>NpgsqlConnection</c>) and runs the supplied <paramref name="action"/> against it.
    /// The scope (and its connection) is disposed when the action completes, even on exception.
    /// This is the safe pattern for any test-side database access in the production HTTP fixture
    /// — it avoids the captive-singleton race that otherwise serialises everything onto one
    /// connection and surfaces as <c>NpgsqlOperationInProgressException</c>.
    /// </summary>
    public async Task UseRedbAsync(Func<IRedbService, Task> action)
    {
        ArgumentNullException.ThrowIfNull(action);
        await using var scope = _sp.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        await action(redb).ConfigureAwait(false);
    }

    /// <summary>
    /// Like <see cref="UseRedbAsync(Func{IRedbService, Task})"/> but with a return value.
    /// </summary>
    public async Task<T> UseRedbAsync<T>(Func<IRedbService, Task<T>> action)
    {
        ArgumentNullException.ThrowIfNull(action);
        await using var scope = _sp.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        return await action(redb).ConfigureAwait(false);
    }

    /// <summary>
    /// Bearer token with <c>identity:manage</c> scope for management API calls.
    /// </summary>
    public string ManagementToken { get; private set; } = null!;

    /// <summary>
    /// Bearer token with <c>scim</c> scope for SCIM provisioning API calls.
    /// </summary>
    public string ScimToken { get; private set; } = null!;

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

        // Real PostgreSQL + Pro with DeleteInsert
        services.AddRedbForTests(cs);

        services.AddSingleton<SharedVmRegistry>();

        // Identity options — production mode
        var identityOptions = new RedbIdentityOptions
        {
            TokenRetentionDays = 30,
            TokenThrottleMaxPerPeriod = 1000,
            TokenThrottlePeriod = TimeSpan.FromSeconds(1),
            Issuer = new Uri($"http://localhost:{Port}/"),
            AllowEphemeralKeys = true,
            DisableAccessTokenEncryption = true,
            // Enable conditional features for E2E testing
            Features = new IdentityFeatureFlags
            {
                EnableDynamicRegistration = true,
                EnableDeviceCodeFlow = true,
                EnableScim = true,
                EnableScimBulk = true,
                EnablePushedAuthorization = true,
            },
            DynamicRegistrationInitialAccessToken = DynamicRegAccessToken,
            DynamicRegistrationAllowedGrantTypes =
                ["authorization_code", "refresh_token", "client_credentials"],
            // Bump DCR throttle so a long-running test suite (~11 DCR tests in this
            // collection alone) does not stall on the per-IP window.
            DynamicRegistrationThrottleMaxPerPeriod = 1000,
            DynamicRegistrationThrottlePeriod = TimeSpan.FromSeconds(1),
            EnablePasswordFlow = true,
            // Scope-authorization gate (B0.1): user-bound token requests for
            // "identity:admin" must belong to group "identity-admins".
            // client_credentials flows are unaffected (no user identity).
            ScopeRequiredGroups = new(StringComparer.Ordinal)
            {
                [AdminGatedScope] = AdminGroupName
            },
            // Z4: enable DPoP in soft mode — clients opt-in by sending the header.
            Dpop = new DpopOptions
            {
                Enabled = true,
                RequireForAccessTokens = false,
            },
            // Disable the MFA OTP cleanup timer to avoid background interference in tests.
            MfaOtpCleanupInterval = System.Threading.Timeout.InfiniteTimeSpan,
        };
        // N-3 (sub-step N3-7): enable self-service registration so FullStackAccountRegistrationTests
        // can exercise the public /api/v1/identity/account/register endpoint. The feature gate
        // defaults to OFF; flipping it on here is harmless to other tests in this collection
        // (none of them touch the register route or the AccountRegister direct-vm).
        identityOptions.Registration.Enabled = true;
        // B1 — enable the emergency-admin bootstrap endpoint with a known secret.
        // The endpoint is mounted unconditionally; the processor short-circuits on
        // the Enabled flag. Tests in BootstrapAdminTests clean the bootstrap_completed
        // sentinel + identity-web client between cases so each test sees pristine state.
        identityOptions.Bootstrap.Enabled = true;
        identityOptions.Bootstrap.Secret = BootstrapSecret;
        identityOptions.Bootstrap.WebClientId = BootstrapWebClientId;
        identityOptions.Bootstrap.AdminScope = BootstrapAdminScope;
        identityOptions.Bootstrap.AdminGroupName = BootstrapAdminGroup;
        // SeedWebClientHostedService.OnContextStarting seeds an OIDC client with the
        // default ClientId "identity-web", which is identical to BootstrapWebClientId.
        // The seed runs once at fixture startup; CleanupBootstrapStateAsync removes
        // the row before each test, but in practice the row keeps coming back via
        // a stale higher-level cache entry, so every "first call" test sees the
        // pre-seeded client and returns 409 (duplicate). Disabling the seed here lets
        // the bootstrap tests own the lifecycle of the canonical client end-to-end
        // — the only fixture in the suite that actually exercises that lifecycle.
        identityOptions.SeedWebClient.Enabled = false;
        services.AddSingleton(Options.Create(identityOptions));

        // H6/H7/H9: enable audit + PROPS persistence so e2e protocol tests can assert audit emission.
        services.AddSingleton(Options.Create(new IdentityAuditOptions
        {
            Enabled = true,
            Filter = "*",
            PersistToProps = true,
            Targets = []
        }));

        // HTTP transport options. Features instance is *shared* with the Core options
        // — single source of truth keeps Core (DI / direct-vm gating) and Http (route
        // mounting) in lockstep, mirroring the Identity:Features:* shared section in
        // production context.json.
        var transportOptions = new IdentityTransportOptions();
        transportOptions.Http.PublicPort = Port;
        // Single-instance shared section (Issuer + Features) — replaces the
        // previous per-property mirror. Mirrors the architectural invariant
        // that Issuer and Features are bound from one Identity:* section in
        // context.json.
        transportOptions.Shared = identityOptions.Shared;
        services.AddSingleton(Options.Create(transportOptions));

        // *** PRODUCTION bootstrap — real OpenIddict stores + pipeline ***
        services.AddRedbIdentityServer(identityOptions);

        // N-4 (Session C): capture transactional e-mails in memory so tests can assert
        // delivery + extract reset tokens. Registered AFTER AddRedbIdentityServer because
        // Core leaves IEmailNotificationChannel unbound by default (production hosts pick
        // SMTP / SendGrid). We register the concrete type as a singleton and expose it via
        // the interface so the channel implementation and the test-side captured-message
        // reader share one instance.
        services.AddSingleton<InMemoryEmailNotificationChannel>(sp =>
            new InMemoryEmailNotificationChannel(sp.GetRequiredService<IEmailTemplateRegistry>()));
        services.AddSingleton<IEmailNotificationChannel>(
            sp => sp.GetRequiredService<InMemoryEmailNotificationChannel>());

        // TODO: enable ValidateScopes=true here once the fixture's _sp.GetRequiredService<>
        // calls below + the captive `public IRedbService Redb` field are reworked to use a
        // dedicated init scope and a per-call scope helper. ASP.NET Core does this in
        // Development by default and it would surface captive-singleton bugs at resolve
        // time instead of letting them silently serialize concurrent requests onto a
        // single NpgsqlConnection (see DisableEntityCaching + per-exchange resolve fix).
        _sp = services.BuildServiceProvider();

        // Initialize PostgreSQL schema. The init / schema-sync / seed phase runs strictly
        // serial here on a single dedicated DI scope (one connection from the pool) — no
        // concurrent HTTP traffic exists yet (HttpComponent is started below).
        await using (var initScope = _sp.CreateAsyncScope())
        {
            var initRedb = initScope.ServiceProvider.GetRequiredService<IRedbService>();
            try { await initRedb.InitializeAsync(ensureCreated: true); }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"InitializeAsync(ensureCreated:true) failed, falling back: {ex.GetType().Name}: {ex.Message}");
                await initRedb.InitializeAsync();
            }

            await initRedb.SyncSchemeAsync<ApplicationProps>();
            await initRedb.SyncSchemeAsync<AuthorizationProps>();
            await initRedb.SyncSchemeAsync<ScopeProps>();
            await initRedb.SyncSchemeAsync<TokenProps>();
            await initRedb.SyncSchemeAsync<UserProps>();
            await initRedb.SyncSchemeAsync<DataProtectionKeyProps>();
            await initRedb.SyncSchemeAsync<SessionProps>();
            await initRedb.SyncSchemeAsync<MfaProps>();
            await initRedb.SyncSchemeAsync<GroupProps>();
            await initRedb.SyncSchemeAsync<GroupMemberProps>();
            // R1: AuditEventProps removed — identity_audit_log is now a flat
            // relational table created by IdentityAuditLogTableInitListener
            // (not via props scheme sync).
            // H5: ClaimMapper schemes — required by AttachClaimMapperClaims handler in the
            // OpenIddict ProcessSignInContext pipeline. Without these the resolver query
            // would throw at every token issuance.
            await initRedb.SyncSchemeAsync<ClaimMapperProps>();
            await initRedb.SyncSchemeAsync<ClaimScopeProps>();
            await initRedb.SyncSchemeAsync<ClaimScopeAssignmentProps>();
            await initRedb.InitializeTypeRegistryAsync();
        }

        // Fix btree index overflow for large Payload values (4+ scope tokens)
        await IndexFixHelper.FixValueStringIndexAsync(cs);

        // Seed test data via OpenIddict managers (BCrypt-hashed secrets)
        await SeedTestClients();
        await SeedTestUser();
        await SeedAdminUserAndGroup();

        // Create RouteContext with HTTP
        _ctx = new RouteContext(_sp, "production-http-e2e");
        _ctx.AddComponent(new HttpComponent { ServerManager = new SharedHttpServerManager() });

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

        _ctx.AddRoutes(new IdentityCoreRouteBuilder(_sp, Options.Create(identityOptions),
            Options.Create(new IdentityAuditOptions { Enabled = true, Filter = "*", PersistToProps = true, Targets = [] }),
            managementAuth,
            scimAuth));

        _ctx.AddRoutes(new HttpFacadeRouteBuilder(
            new SessionTicketService(_sp.GetRequiredService<IDataProtectionProvider>()),
            Options.Create(transportOptions),
            // Phase 9e: post_logout_redirect_uri validator routes through the
            // direct-vm broker registered by IdentityCoreRouteBuilder. Without this
            // the facade's validator delegate stays null → every logout falls back
            // to the "Signed Out" page, even for registered URIs.
            new redb.Identity.Http.Endpoints.BrokeredPostLogoutRedirectValidator(_ctx)));

        // identity_audit_log is a flat relational table created by
        // IdentityAuditLogTableInitListener (registered by Core/Module InitRoute
        // in tpkg deployments). The fixture builds its own RouteContext and
        // skips that path — register the listener directly so the table is
        // ensured on every provider. Without this, Postgres tests pass only
        // because earlier runs persisted the table; SQLite gets a fresh temp
        // file per call and sees "no such table: identity_audit_log".
        _ctx.AddLifecycleListener(new redb.Identity.Core.Module.IdentityAuditLogTableInitListener(_sp));

        await _ctx.Start();

        Producer = new ProducerTemplate(_ctx);
        Producer.Start();

        Http = new HttpClient { BaseAddress = new Uri(BaseUrl) };

        ManagementToken = await ObtainManagementTokenAsync();
        ScimToken = await ObtainScimTokenAsync();
    }

    public async Task DisposeAsync()
    {
        Http.Dispose();
        Producer.Stop();
        Producer.Dispose();

        // Dispose the single captive scope (if Redb was ever accessed). Each scope owns an
        // NpgsqlConnection borrowed from the pool; without explicit disposal it would only
        // return to the pool when _sp itself is disposed, which can race with in-flight
        // commands and surface as NpgsqlOperationInProgressException during teardown.
        if (_captiveScope is { } captive)
        {
            try { await captive.DisposeAsync().ConfigureAwait(false); }
            catch (Exception ex)
            {
                Console.Error.WriteLine(
                    $"[ProductionHttpFixture] captive-scope.DisposeAsync() threw: {ex.GetType().Name}: {ex.Message}");
            }
            _captiveScope = null;
            _captiveRedb = null;
        }

        // Bound the route-context teardown to a short timeout so a misbehaving processor
        // (one that doesn't honour cancellation in its disposal path) cannot wedge the
        // entire test host. Without this, blame-collector trips after 3 minutes and the
        // run is aborted before later collections / dispose hooks complete. Best-effort:
        // if a route is genuinely stuck we leak it for the lifetime of the test process,
        // which is acceptable in a teardown path.
        try
        {
            using var ctsCtx = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var disposeCtx = _ctx.DisposeAsync().AsTask();
            var winner = await Task.WhenAny(disposeCtx, Task.Delay(Timeout.Infinite, ctsCtx.Token));
            if (winner != disposeCtx)
            {
                Console.Error.WriteLine(
                    "[ProductionHttpFixture] _ctx.DisposeAsync() did not complete within 15s; continuing teardown.");
            }
            else
            {
                await disposeCtx;
            }
        }
        catch (OperationCanceledException) { /* timeout — leak */ }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ProductionHttpFixture] _ctx.DisposeAsync() threw: {ex.GetType().Name}: {ex.Message}");
        }

        try
        {
            using var ctsSp = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var disposeSp = _sp.DisposeAsync().AsTask();
            var winner = await Task.WhenAny(disposeSp, Task.Delay(Timeout.Infinite, ctsSp.Token));
            if (winner != disposeSp)
            {
                Console.Error.WriteLine(
                    "[ProductionHttpFixture] _sp.DisposeAsync() did not complete within 10s; continuing teardown.");
            }
            else
            {
                await disposeSp;
            }
        }
        catch (OperationCanceledException) { /* timeout — leak */ }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ProductionHttpFixture] _sp.DisposeAsync() threw: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private async Task SeedTestClients()
    {
        var manager = _sp.GetRequiredService<IOpenIddictApplicationManager>();

        foreach (var clientId in new[] { TestClientId, TestPublicClientId, TestMgmtClientId, TestConsentClientId })
        {
            var existing = await manager.FindByClientIdAsync(clientId);
            if (existing is not null)
                await manager.DeleteAsync(existing);
        }

        // Confidential client — client_credentials + auth_code + refresh + introspect + revoke + password
        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = TestClientId,
            ClientSecret = TestClientSecret,
            ClientType = OpenIddictConstants.ClientTypes.Confidential,
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
            DisplayName = "E2E Confidential Client",
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
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Phone,
                OpenIddictConstants.Permissions.Prefixes.Scope + "openid",
                OpenIddictConstants.Permissions.Prefixes.Scope + "offline_access",
                OpenIddictConstants.Permissions.Prefixes.Scope + "groups",
                OpenIddictConstants.Permissions.Prefixes.Scope + "roles",
                OpenIddictConstants.Permissions.Prefixes.Scope + AdminGatedScope,
                OpenIddictConstants.Permissions.ResponseTypes.Code
            },
            RedirectUris = { new Uri(TestRedirectUri) },
            PostLogoutRedirectUris = { new Uri(TestRedirectUri) },
            Requirements = { OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange }
        });

        // Public PKCE client (+ device code flow)
        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = TestPublicClientId,
            ClientType = OpenIddictConstants.ClientTypes.Public,
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
            DisplayName = "E2E Public PKCE Client",
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.DeviceAuthorization,
                OpenIddictConstants.Permissions.Endpoints.PushedAuthorization,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                OpenIddictConstants.Permissions.GrantTypes.DeviceCode,
                OpenIddictConstants.Permissions.Prefixes.Scope + "openid",
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Prefixes.Scope + "offline_access",
                // W6-debt: allow self-service /me/* endpoints to be exercised end-to-end
                // through the same public PKCE client (auth code flow → token with sid).
                OpenIddictConstants.Permissions.Prefixes.Scope + "identity:account",
                OpenIddictConstants.Permissions.ResponseTypes.Code
            },
            RedirectUris = { new Uri(TestRedirectUri) },
            Requirements = { OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange }
        });

        // Management client — client_credentials + identity:manage scope
        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = TestMgmtClientId,
            ClientSecret = TestMgmtSecret,
            ClientType = OpenIddictConstants.ClientTypes.Confidential,
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
            DisplayName = "E2E Management Client",
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.Introspection,
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                OpenIddictConstants.Permissions.Prefixes.Scope + "identity:manage",
                OpenIddictConstants.Permissions.Prefixes.Scope + AdminGatedScope,
                OpenIddictConstants.Permissions.Prefixes.Scope + "scim"
            }
        });

        // Explicit consent client — requires user consent page
        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = TestConsentClientId,
            ClientType = OpenIddictConstants.ClientTypes.Public,
            ConsentType = OpenIddictConstants.ConsentTypes.Explicit,
            DisplayName = "E2E Explicit Consent App",
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.Prefixes.Scope + "openid",
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Email,
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
                Email = "e2e@example.com",
                Phone = "+1999888777",
                Enabled = true
            });
        }

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
        oidcObj.Props.EmailVerified = true;
        oidcObj.Props.GivenName = "E2E";
        oidcObj.Props.FamilyName = "Tester";
        oidcObj.Props.PhoneNumberVerified = true;
        await Redb.SaveAsync(oidcObj);
    }

    /// <summary>
    /// Seed admin user (<see cref="TestAdminUsername"/>) and add to group
    /// <see cref="AdminGroupName"/>. Used to exercise the
    /// <c>RestrictScopeByGroupMembershipHandler</c> via password grant.
    /// </summary>
    private async Task SeedAdminUserAndGroup()
    {
        // Admin user
        var adminUser = await Redb.UserProvider.GetUserByLoginAsync(TestAdminUsername);
        if (adminUser is null)
        {
            adminUser = await Redb.UserProvider.CreateUserAsync(new redb.Core.Models.Users.CreateUserRequest
            {
                Login = TestAdminUsername,
                Password = TestAdminPassword,
                Name = TestAdminUsername,
                Email = "e2e-admin@example.com",
                Phone = "+1999000111",
                Enabled = true
            });
        }

        // OIDC props (required for token issuance — password flow loads them)
        var adminOidc = await Redb.Query<UserProps>()
            .WhereRedb(o => o.Key == adminUser.Id)
            .FirstOrDefaultAsync();
        if (adminOidc is null)
        {
            adminOidc = new RedbObject<UserProps>(new UserProps());
            adminOidc.name = TestAdminUsername;
            adminOidc.key = adminUser.Id;
            adminOidc.value_guid = Guid.NewGuid();
        }
        adminOidc.Props.EmailVerified = true;
        adminOidc.Props.GivenName = "E2E";
        adminOidc.Props.FamilyName = "Admin";
        adminOidc.Props.PhoneNumberVerified = true;
        await Redb.SaveAsync(adminOidc);

        // Admin group — ensure exists, idempotent across fixture re-runs
        var groupService = new redb.Identity.Core.Services.GroupService(Redb);
        var existingGroup = await Redb.Query<redb.Identity.Core.Models.GroupProps>()
            .WhereRedb(o => o.Name == AdminGroupName)
            .FirstOrDefaultAsync();

        long groupId;
        if (existingGroup is null)
        {
            var created = await groupService.CreateGroupAsync(AdminGroupName, "role", "Admin role group");
            groupId = created.Id;
        }
        else
        {
            groupId = existingGroup.Id;
        }

        // Membership — silently skip if already present (re-runs)
        var alreadyMember = await Redb.Query<redb.Identity.Core.Models.GroupMemberProps>()
            .WhereRedb(o => o.Key == adminUser.Id && o.ParentId == groupId)
            .FirstOrDefaultAsync();
        if (alreadyMember is null)
        {
            await groupService.AddMemberAsync(groupId, adminUser.Id, role: "admin");
        }
    }

    private async Task<string> ObtainManagementTokenAsync()
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = TestMgmtClientId,
            ["client_secret"] = TestMgmtSecret,
            ["scope"] = "identity:manage"
        });

        var response = await Http.PostAsync("/connect/token", content);
        if (!response.IsSuccessStatusCode)
        {
            var error = await response.Content.ReadAsStringAsync();
            throw new InvalidOperationException(
                $"Management token request failed ({response.StatusCode}): {error}");
        }

        var json = await JsonSerializer.DeserializeAsync<JsonElement>(
            await response.Content.ReadAsStreamAsync());
        return json.GetProperty("access_token").GetString()
               ?? throw new InvalidOperationException("Missing access_token in response");
    }

    private async Task<string> ObtainScimTokenAsync()
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = TestMgmtClientId,
            ["client_secret"] = TestMgmtSecret,
            ["scope"] = "scim"
        });

        var response = await Http.PostAsync("/connect/token", content);
        if (!response.IsSuccessStatusCode)
        {
            var error = await response.Content.ReadAsStringAsync();
            throw new InvalidOperationException(
                $"SCIM token request failed ({response.StatusCode}): {error}");
        }

        var json = await JsonSerializer.DeserializeAsync<JsonElement>(
            await response.Content.ReadAsStreamAsync());
        return json.GetProperty("access_token").GetString()
               ?? throw new InvalidOperationException("Missing access_token in response");
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

[CollectionDefinition("ProductionHttp")]
public class ProductionHttpCollection : ICollectionFixture<ProductionHttpFixture>;
