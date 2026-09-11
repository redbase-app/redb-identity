using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Validation;
using redb.Core;
using redb.Identity.Core;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Core.Routes;
using redb.Identity.Core.Routes.Processors;
using redb.Identity.Soap;
using redb.Route.Components;
using redb.Route.Core;
using redb.Route.Soap;
using Xunit;

namespace redb.Identity.Tests.Infrastructure;

/// <summary>
/// Boots redb.Identity.Core plus the WS-Trust facade in one process against the real PostgreSQL store,
/// with the <b>production</b> OpenIddict pipeline and a real client registry — not degraded mode. The same
/// reasoning as the gRPC fixture: a degraded stack skips client validation and keeps no token store, so it
/// could neither refuse a wrong secret nor make a revoked token go inactive, and a test claiming either
/// would be theatre.
/// <para>
/// Requests are composed as raw SOAP envelopes and posted with an ordinary HttpClient rather than through
/// a generated proxy. That is deliberate: the whole point of this facade is that someone else's generator
/// can talk to it, so the wire has to be the thing under test.
/// </para>
/// <para>
/// TLS is off here through <c>AllowPlaintext</c> — the documented escape hatch for a terminated
/// connection. A self-signed certificate would test our own certificate handling, not the protocol, and
/// the refusal itself is covered by <c>SoapFacadeModuleTests</c>.
/// </para>
/// </summary>
public class SoapIdentityFixture : IAsyncLifetime
{
    /// <summary>
    /// Last word on the server options, for fixtures that need a stack tuned differently. The base
    /// settings are deliberately permissive so ordinary tests never trip a limiter by accident.
    /// </summary>
    protected virtual void Tune(RedbIdentityOptions options) { }

    public const string ClientId = "soap-e2e-client";
    public const string ClientSecret = "soap-e2e-secret";
    public const string GrantedScope = "identity:manage";

    private ServiceProvider _sp = null!;
    private RouteContext _coreContext = null!;
    private RouteContext _ctx = null!;
    private HttpClient _http = null!;

    public int Port { get; private set; }
    public IRedbService Redb { get; private set; } = null!;

    private const string StsPath = "/sts";

    public async Task InitializeAsync()
    {
        Port = GetFreePort();

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
            Issuer = new Uri($"http://localhost:{Port}/"),
            AllowEphemeralKeys = true,
            DisableAccessTokenEncryption = true,
        };
        Tune(identityOptions);
        services.AddSingleton(Options.Create(identityOptions));

        var transportOptions = new IdentitySoapTransportOptions
        {
            // One shared instance, the invariant every facade fixture keeps: issuer and feature flags come
            // from a single section rather than being mirrored property by property.
            Shared = identityOptions.Shared,
        };
        transportOptions.Soap.Host = "127.0.0.1";
        transportOptions.Soap.Port = Port;
        transportOptions.Soap.Path = StsPath;
        transportOptions.Soap.Ssl = false;
        transportOptions.Soap.AllowPlaintext = true;
        services.AddSingleton(Options.Create(transportOptions));

        services.AddRedbIdentityServer(identityOptions);

        _sp = services.BuildServiceProvider();

        Redb = _sp.GetRequiredService<IRedbService>();
        try { await Redb.InitializeAsync(ensureCreated: true); }
        catch { await Redb.InitializeAsync(); }

        await Redb.SyncSchemeAsync<ApplicationProps>();
        await Redb.SyncSchemeAsync<AuthorizationProps>();
        await Redb.SyncSchemeAsync<ScopeProps>();
        await Redb.SyncSchemeAsync<TokenProps>();
        await Redb.InitializeTypeRegistryAsync();

        await SeedClient();

        // Two contexts, not one — the way Tsak actually runs them. Core owns "identity", the facade owns
        // "identity.soap", and they meet only over direct-vm through the shared registry in DI.
        //
        // This is not tidiness. Core registers a context-wide OnException<Exception>().Handled() catch-all,
        // and inside one shared context it also swallows the facade's own faults: a refusal would come back
        // as an empty envelope instead of a soap:Fault, and a fixture built that way would prove the
        // opposite of what production does.
        _coreContext = new RouteContext(_sp, "identity");

        redb.Route.Abstractions.IProcessor managementAuth = new ManagementBearerAuthProcessor(
            _sp.GetRequiredService<IOpenIddictValidationFactory>(),
            _sp.GetRequiredService<IOpenIddictValidationDispatcher>(),
            new[] { identityOptions.ManagementScope, identityOptions.AccountScope });

        _coreContext.AddRoutes(new IdentityCoreRouteBuilder(_sp, Options.Create(identityOptions),
            auditOptions: null, managementAuth: managementAuth, scimAuth: null));

        await _coreContext.Start();

        _ctx = new RouteContext(_sp, "identity.soap");
        _ctx.AddComponent(new SoapComponent());
        _ctx.AddRoutes(new SoapFacadeRouteBuilder(Options.Create(transportOptions)));

        await _ctx.Start();

        _http = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{Port}") };
    }

    public async Task DisposeAsync()
    {
        _http?.Dispose();
        if (_ctx is not null) await _ctx.DisposeAsync();
        if (_coreContext is not null) await _coreContext.DisposeAsync();
        if (_sp is not null) await _sp.DisposeAsync();
    }

    /// <summary>
    /// Registers the confidential client the tests authenticate as. The manager hashes the secret, which
    /// is what makes «a wrong secret is refused» a real assertion rather than a formality.
    /// </summary>
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
            DisplayName = "SOAP E2E client",
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.Introspection,
                OpenIddictConstants.Permissions.Endpoints.Revocation,
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                OpenIddictConstants.Permissions.Prefixes.Scope + GrantedScope,
            },
        });
    }

    // ── the wire ─────────────────────────────────────────────

    /// <summary>
    /// Posts a WS-Trust request and returns the raw response envelope, whatever it is. Faults come back
    /// as envelopes too, so a test can read the fault code rather than only observing that something
    /// failed.
    /// </summary>
    public async Task<string> PostAsync(string action, string rstBody,
        string? username = ClientId, string? password = ClientSecret)
    {
        var envelope = BuildEnvelope(rstBody, username, password);

        using var content = new StringContent(envelope, Encoding.UTF8, "text/xml");
        content.Headers.Add("SOAPAction", $"\"{action}\"");

        using var response = await _http.PostAsync(StsPath, content);
        return await response.Content.ReadAsStringAsync();
    }

    /// <summary>Fetches the published contract, the way a client developer's generator would.</summary>
    public async Task<HttpResponseMessage> GetWsdlAsync() =>
        await _http.GetAsync(StsPath + "?wsdl");

    /// <summary>
    /// A SOAP 1.1 envelope with a WS-Security UsernameToken, which is how a WS-Trust caller presents its
    /// client credentials.
    /// </summary>
    private static string BuildEnvelope(string rstBody, string? username, string? password)
    {
        const string wsse =
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";

        var security = username is null
            ? string.Empty
            : $"""
               <soap:Header>
                 <wsse:Security xmlns:wsse="{wsse}">
                   <wsse:UsernameToken>
                     <wsse:Username>{username}</wsse:Username>
                     <wsse:Password>{password}</wsse:Password>
                   </wsse:UsernameToken>
                 </wsse:Security>
               </soap:Header>
               """;

        return $"""
                <?xml version="1.0" encoding="utf-8"?>
                <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
                  {security}
                  <soap:Body>
                    {rstBody}
                  </soap:Body>
                </soap:Envelope>
                """;
    }

    private static int GetFreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}

/// <summary>
/// The same stack with the per-IP limiter turned on. Core keys that limiter on
/// <c>redbHttp.RemoteAddress</c>, a header a SOAP request has none of on its own: the listener puts it
/// there because the facade asks for <c>EmitHttpCompatHeaders</c>. If that bridge ever breaks the
/// limiter does not fail loudly — it silently stops protecting this port, and every other test in the
/// suite still passes. This fixture exists so one of them would not.
/// </summary>
public sealed class SoapThrottledIdentityFixture : SoapIdentityFixture
{
    /// <summary>Requests one IP may make per minute before Core answers 429.</summary>
    public const int PerIpPerMinute = 3;

    protected override void Tune(RedbIdentityOptions options)
    {
        options.RateLimit.Enabled = true;
        options.RateLimit.PerIpPerMinute = PerIpPerMinute;
    }
}
