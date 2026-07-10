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
/// E2E fixture for federation tests against a real mock-oauth2-server (navikt).
/// Requires the <c>route-mock-oauth2</c> container running on port 9199.
/// Uses <see cref="OidcFederatedAuthProvider"/> (real OIDC client) instead of FakeFederatedAuthProvider.
/// </summary>
public sealed class MockOidcE2EFixture : IAsyncLifetime
{
    private ServiceProvider _sp = null!;
    private RouteContext _ctx = null!;

    /// <summary>mock-oauth2-server authority (issuer "default").</summary>
    public const string Authority = "http://localhost:9199/default";

    /// <summary>mock-oauth2-server accepts any client_id/secret.</summary>
    public const string MockClientId = "redb-e2e-client";
    public const string MockClientSecret = "redb-e2e-secret";
    public const string ProviderId = "mock-oidc";

    public const string TestUsername = "e2e-fed-testuser";
    public const string TestPassword = "E2eTest@Password123";

    /// <summary>Callback URL that OidcFederatedAuthProvider embeds in authorize request.</summary>
    public const string CallbackUrl = "http://localhost/federation/callback";

    public ProducerTemplate Producer { get; private set; } = null!;

    /// <summary>
    /// Captive root-scoped <see cref="IRedbService"/>. <b>NOT thread-safe across
    /// concurrent calls</b> — see the same property on
    /// <see cref="ProductionBootstrapFixture"/> for the full rationale. Use
    /// <see cref="WithRedb{T}"/> / <see cref="WithRedb"/> for any path that may
    /// run concurrently with the Worker's route processing.
    /// </summary>
    public IRedbService Redb { get; private set; } = null!;

    /// <summary>
    /// Run <paramref name="action"/> against a <b>fresh, scoped</b>
    /// <see cref="IRedbService"/>. See <see cref="ProductionBootstrapFixture.WithRedb{T}"/>
    /// for the rationale (concurrent-NpgsqlConnection / shared SqlConnection /
    /// SqliteException(SQLITE_BUSY) classes of failure when the captive Redb is
    /// accessed while the Worker's WireTap audit pipeline is mid-write).
    /// </summary>
    public async Task<T> WithRedb<T>(Func<IRedbService, Task<T>> action)
    {
        if (action is null) throw new ArgumentNullException(nameof(action));
        using var scope = _sp.CreateScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        return await action(redb).ConfigureAwait(false);
    }

    /// <summary>Void-result overload of <see cref="WithRedb{T}"/>.</summary>
    public async Task WithRedb(Func<IRedbService, Task> action)
    {
        if (action is null) throw new ArgumentNullException(nameof(action));
        using var scope = _sp.CreateScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        await action(redb).ConfigureAwait(false);
    }

    public IServiceProvider ServiceProvider => _sp;
    public long TestUserId { get; private set; }

    /// <summary>Pre-configured HttpClient for interacting with mock-oauth2-server.</summary>
    public HttpClient MockOidcHttpClient { get; } = new(new HttpClientHandler
    {
        AllowAutoRedirect = false
    });

    /// <summary>Returns true if mock-oauth2-server is reachable.</summary>
    public bool IsServerAvailable { get; private set; }

    public async Task InitializeAsync()
    {
        // Check if mock-oauth2-server is available
        IsServerAvailable = await CheckServerAsync();
        if (!IsServerAvailable)
            return; // tests will skip via Skip attribute / guard

        var config = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json")
            .Build();

        var cs = config.GetConnectionString("Postgres")
                 ?? throw new InvalidOperationException("ConnectionStrings:Postgres not found");

        var services = new ServiceCollection();
        services.AddLogging(b => b.SetMinimumLevel(LogLevel.Warning));

        services.AddRedbForTests(cs);

        services.AddSingleton<SharedVmRegistry>();

        var providerConfig = new FederationProviderConfig
        {
            ProviderId = ProviderId,
            DisplayName = "Mock OIDC Server",
            Authority = Authority,
            ClientId = MockClientId,
            ClientSecret = MockClientSecret,
            Scopes = ["openid", "profile", "email"]
        };

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
            FederationProviders = [providerConfig]
        };
        services.AddSingleton(Options.Create(identityOptions));

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

        await SeedTestUser();

        _ctx = new RouteContext(_sp, "e2e-federation-integration");
        _ctx.AddRoutes(new IdentityCoreRouteBuilder(_sp, Options.Create(identityOptions)));
        await _ctx.Start();

        Producer = new ProducerTemplate(_ctx);
        Producer.Start();
    }

    public async Task DisposeAsync()
    {
        MockOidcHttpClient.Dispose();

        if (!IsServerAvailable) return;

        Producer.Stop();
        Producer.Dispose();
        await _ctx.DisposeAsync();
        await _sp.DisposeAsync();
    }

    public async Task<object?> Request(string endpointUri, object body)
    {
        return await Producer.RequestBody(endpointUri, body);
    }

    /// <summary>
    /// H8: send a request with explicit headers (needed by management processors that
    /// dispatch on the <c>operation</c> header).
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

    /// <summary>
    /// Simulates the browser-side interactive login on mock-oauth2-server.
    /// POSTs username to the authorize URL → gets 302 redirect with code.
    /// Returns (code, state) from the redirect Location header.
    /// </summary>
    public async Task<(string code, string state)> SimulateInteractiveLogin(
        string authorizeUrl, string username = "e2e-test-user")
    {
        // POST to the authorize URL with username (mock-oauth2-server interactive login form)
        var formContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = username
        });

        var response = await MockOidcHttpClient.PostAsync(authorizeUrl, formContent);

        if (response.StatusCode != System.Net.HttpStatusCode.Found)
            throw new InvalidOperationException(
                $"Expected 302 redirect from mock-oauth2-server, got {response.StatusCode}");

        var location = response.Headers.Location?.ToString()
            ?? throw new InvalidOperationException("No Location header in mock-oauth2-server redirect");

        var code = ExtractQueryParam(location, "code")
            ?? throw new InvalidOperationException("No 'code' parameter in redirect URL");
        var state = ExtractQueryParam(location, "state")
            ?? throw new InvalidOperationException("No 'state' parameter in redirect URL");

        return (code, state);
    }

    internal static string? ExtractQueryParam(string url, string paramName)
    {
        var uri = new Uri(url, UriKind.RelativeOrAbsolute);
        if (!uri.IsAbsoluteUri)
            uri = new Uri("http://dummy" + url);

        var query = uri.Query.TrimStart('?');
        foreach (var pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = pair.Split('=', 2);
            if (parts.Length == 2 && parts[0] == paramName)
                return Uri.UnescapeDataString(parts[1]);
        }
        return null;
    }

    private async Task<bool> CheckServerAsync()
    {
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            var response = await MockOidcHttpClient.GetAsync(
                $"{Authority}/.well-known/openid-configuration", cts.Token);
            return response.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
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
                Email = "e2e-fed@example.com",
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
        oidcObj.Props.GivenName = "E2E";
        oidcObj.Props.FamilyName = "TestUser";
        await Redb.SaveAsync(oidcObj);
    }
}

[CollectionDefinition("MockOidcE2E")]
public class MockOidcE2ECollection : ICollectionFixture<MockOidcE2EFixture>;
