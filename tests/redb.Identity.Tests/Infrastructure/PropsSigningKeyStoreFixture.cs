using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using redb.Core;
using redb.Identity.Core;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Keys;
using redb.Identity.Core.Models;
using redb.Identity.Core.Routes;
using redb.Identity.DataProtection;
using redb.Route.Components;
using redb.Route.Core;
using Xunit;

namespace redb.Identity.Tests.Infrastructure;

/// <summary>
/// The production key path, end to end: OpenIddict fed from the redb-backed
/// <see cref="ISigningKeyStore"/>, no ephemeral keys.
/// <para>
/// Every other fixture runs on ephemeral keys, which is the right default for tests that are about
/// something else — but it means rotation and retirement never met a real token pipeline in the suite.
/// This fixture is for exactly that: mint here, rotate and retire through the store, and ask the same
/// server and validation stacks whether the token still holds. Access-token encryption is off so the
/// token is a plain JWS and its <c>kid</c> can be read back, which turns "which key signed this" from an
/// inference into an assertion.
/// </para>
/// <para>
/// Own client, own context: nothing here is shared with <see cref="ProductionBootstrapFixture"/>, so the
/// two never reseed each other's data.
/// </para>
/// </summary>
public sealed class PropsSigningKeyStoreFixture : IAsyncLifetime
{
    public const string ClientId = "signing-keys-e2e-client";
    public const string ClientSecret = "signing-keys-e2e-secret";
    public const string Scope = "openid";

    private ServiceProvider _sp = null!;
    private RouteContext _ctx = null!;

    public IServiceProvider ServiceProvider => _sp;
    public ISigningKeyStore Store => _sp.GetRequiredService<ISigningKeyStore>();
    public ProducerTemplate Producer { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        var config = new ConfigurationBuilder().AddJsonFile("appsettings.json").Build();
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
            Issuer = new Uri("https://identity.keys.test.local/"),
            // The point of this fixture: persistent keys from the store, nothing ephemeral to fall back on.
            UsePropsSigningKeyStore = true,
            AllowEphemeralKeys = false,
            // Plain JWS access tokens, so a test can read the kid that signed them.
            DisableAccessTokenEncryption = true,
            // Without ephemeral keys the key ring must be protected at rest, as in production. A fixed test
            // master key: the ring only ever holds this fixture's keys.
            DataProtection = new DataProtectionOptions
            {
                MasterKey = Convert.ToBase64String(Enumerable.Range(1, 32).Select(i => (byte)i).ToArray()),
            },
        };
        services.AddSingleton(Options.Create(identityOptions));
        services.AddRedbIdentityServer(identityOptions);

        _sp = services.BuildServiceProvider();

        var redb = _sp.GetRequiredService<IRedbService>();
        try { await redb.InitializeAsync(ensureCreated: true); }
        catch { await redb.InitializeAsync(); }

        await redb.SyncSchemeAsync<ApplicationProps>();
        await redb.SyncSchemeAsync<AuthorizationProps>();
        await redb.SyncSchemeAsync<ScopeProps>();
        await redb.SyncSchemeAsync<TokenProps>();
        await redb.SyncSchemeAsync<DataProtectionKeyProps>();
        await redb.SyncSchemeAsync<SigningKeyProps>();
        await redb.InitializeTypeRegistryAsync();

        // What SigningKeyInitListener does in the module: both kinds, before OpenIddict first reads its
        // options — the post-configure that fills the credentials runs on that first read.
        await Store.EnsureBootstrappedAsync("signing");
        await Store.EnsureBootstrappedAsync("encryption");

        await SeedClient();

        _ctx = new RouteContext(_sp, "identity");
        _ctx.AddRoutes(new IdentityCoreRouteBuilder(_sp, Options.Create(identityOptions)));
        await _ctx.Start();

        Producer = new ProducerTemplate(_ctx);
        Producer.Start();
    }

    public async Task DisposeAsync()
    {
        if (_ctx is not null) await _ctx.DisposeAsync();
        if (_sp is not null) await _sp.DisposeAsync();
    }

    /// <summary>Sends a request to a core route and returns the answer body.</summary>
    public Task<object?> Request(string endpointUri, object body) => Producer.RequestBody(endpointUri, body);

    private async Task SeedClient()
    {
        var manager = _sp.GetRequiredService<IOpenIddictApplicationManager>();

        var existing = await manager.FindByClientIdAsync(ClientId);
        if (existing is not null) await manager.DeleteAsync(existing);

        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = ClientId,
            ClientSecret = ClientSecret,
            ClientType = OpenIddictConstants.ClientTypes.Confidential,
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
            DisplayName = "Signing keys E2E client",
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.Introspection,
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                OpenIddictConstants.Permissions.Prefixes.Scope + Scope,
            },
        });
    }
}
