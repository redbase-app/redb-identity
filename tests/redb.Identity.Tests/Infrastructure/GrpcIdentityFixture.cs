using System.Net;
using System.Net.Sockets;
using Google.Protobuf;
using Grpc.Core;
using GrpcMetadata = Grpc.Core.Metadata;
using Grpc.Net.Client;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using redb.Identity.Core.Routes.Processors;
using OpenIddict.Validation;
using redb.Core;
using redb.Identity.Core;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Core.Routes;
using redb.Identity.Grpc;
using redb.Route.Components;
using redb.Route.Core;
using redb.Route.Grpc;
using Xunit;

namespace redb.Identity.Tests.Infrastructure;

/// <summary>
/// Boots redb.Identity.Core plus the gRPC facade in one process against the real PostgreSQL store, with
/// the <b>production</b> OpenIddict pipeline and a real client registry — not degraded mode. That matters:
/// a degraded fixture skips client validation and keeps no token store, so it can neither refuse a wrong
/// secret nor make a revoked token go inactive, and a test claiming either would be theatre.
/// <para>
/// Calls go through raw byte marshallers rather than generated client stubs on purpose: the published
/// contract compiles to messages only (<c>GrpcServices="None"</c>), and exercising it this way proves the
/// wire contract itself instead of a convenience wrapper we also wrote.
/// </para>
/// </summary>
public class GrpcIdentityFixture : IAsyncLifetime
{
    /// <summary>
    /// Last word on the server options, for fixtures that need a stack tuned differently. The base
    /// settings are deliberately permissive so that ordinary tests never trip a limiter by accident.
    /// </summary>
    protected virtual void Tune(RedbIdentityOptions options) { }

    /// <summary>
    /// Bind address. Loopback keeps the ordinary fixtures off every other interface on the machine; the
    /// interop fixture widens it because a client inside a container reaches the host through
    /// host.docker.internal, and a loopback-only listener is invisible from there.
    /// </summary>
    protected virtual string BindHost => "127.0.0.1";

    /// <summary>
    /// Management port. Null means «share the public one», which is the single-node default and the only
    /// branch the ordinary fixtures exercise. <see cref="GrpcSplitPortIdentityFixture"/> takes the other
    /// branch, because a production deployment is expected to firewall the admin surface separately and
    /// an untried split is not a supported configuration.
    /// </summary>
    protected virtual int? ManagementPort => null;

    /// <summary>
    /// Whether Core gets a management authentication processor. False leaves
    /// <c>direct-vm://identity-auth-management</c> unregistered — a deployment mistake, and the one whose
    /// consequences must be checked rather than assumed. See <see cref="GrpcManagementWithoutAuthFixture"/>.
    /// </summary>
    protected virtual bool RegisterManagementAuth => true;

    /// <summary>Where the admin surface actually listens, whichever branch this fixture took.</summary>
    public int EffectiveManagementPort { get; private set; }

    public const string ClientId = "grpc-e2e-client";
    public const string ClientSecret = "grpc-e2e-secret";
    public const string GrantedScope = "identity:manage";

    /// <summary>
    /// A second client, permitted exactly one narrow scope. Without it "a narrow token is refused" cannot
    /// be asserted at all — the master-scope client passes every gate by design.
    /// </summary>
    public const string NarrowClientId = "grpc-e2e-narrow";
    public const string NarrowClientSecret = "grpc-e2e-narrow-secret";
    public const string NarrowScope = "identity:users:read";

    private ServiceProvider _sp = null!;
    private RouteContext _ctx = null!;
    private GrpcChannel _channel = null!;
    private GrpcChannel _managementChannel = null!;

    public int Port { get; private set; }
    public IRedbService Redb { get; private set; } = null!;
    public IServiceProvider ServiceProvider => _sp;

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

        var transportOptions = new IdentityGrpcTransportOptions
        {
            // One shared instance, the same invariant the HTTP fixture keeps: issuer and feature flags
            // come from a single section rather than being mirrored property by property.
            Shared = identityOptions.Shared,
        };
        transportOptions.Grpc.Host = BindHost;
        transportOptions.Grpc.PublicPort = Port;
        transportOptions.Grpc.ManagementPort = ManagementPort;
        EffectiveManagementPort = transportOptions.Grpc.EffectiveManagementPort;
        services.AddSingleton(Options.Create(transportOptions));

        // Production bootstrap: real OpenIddict stores and pipeline, real client validation.
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
        await SeedNarrowClient();

        _ctx = new RouteContext(_sp, "identity-grpc-e2e");
        _ctx.AddComponent(new GrpcComponent());

        // The real bearer-auth processor, built exactly as the HTTP fixture builds it. Passing null here
        // would leave direct-vm://identity-auth-management unregistered, and a management route calling an
        // address that is not there fails open — the one direction an authentication gate must never fail.
        redb.Route.Abstractions.IProcessor? managementAuth = RegisterManagementAuth
            ? new ManagementBearerAuthProcessor(
                _sp.GetRequiredService<IOpenIddictValidationFactory>(),
                _sp.GetRequiredService<IOpenIddictValidationDispatcher>(),
                new[] { identityOptions.ManagementScope, identityOptions.AccountScope, NarrowScope })
            : null;

        _ctx.AddRoutes(new IdentityCoreRouteBuilder(_sp, Options.Create(identityOptions),
            auditOptions: null, managementAuth: managementAuth, scimAuth: null));

        _ctx.AddRoutes(new GrpcFacadeRouteBuilder(Options.Create(transportOptions)));
        _ctx.AddRoutes(new GrpcManagementRouteBuilder(Options.Create(transportOptions)));

        await _ctx.Start();

        _channel = GrpcChannel.ForAddress($"http://127.0.0.1:{Port}");
        _managementChannel = EffectiveManagementPort == Port
            ? _channel
            : GrpcChannel.ForAddress($"http://127.0.0.1:{EffectiveManagementPort}");
    }

    /// <summary>
    /// Registers the confidential client the tests authenticate as. The manager hashes the secret, which
    /// is what makes "a wrong secret is refused" a real assertion rather than a formality.
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
            DisplayName = "gRPC E2E client",
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

    /// <summary>
    /// Registers the narrow-scope client. It may read users and nothing else — which is what makes
    /// "a token that may read is refused a write" an assertion rather than a formality.
    /// </summary>
    private async Task SeedNarrowClient()
    {
        var manager = _sp.GetRequiredService<IOpenIddictApplicationManager>();

        var existing = await manager.FindByClientIdAsync(NarrowClientId);
        if (existing is not null) await manager.DeleteAsync(existing);

        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = NarrowClientId,
            ClientSecret = NarrowClientSecret,
            ClientType = OpenIddictConstants.ClientTypes.Confidential,
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
            DisplayName = "gRPC E2E narrow-scope client",
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                OpenIddictConstants.Permissions.Prefixes.Scope + NarrowScope,
            },
        });
    }

    public async Task DisposeAsync()
    {
        if (!ReferenceEquals(_managementChannel, _channel)) _managementChannel.Dispose();
        _channel.Dispose();
        await _ctx.DisposeAsync();
        await _sp.DisposeAsync();
    }

    /// <summary>Calls a typed operation of the published contract.</summary>
    public async Task<TResponse> CallAsync<TRequest, TResponse>(
        string method, TRequest request, MessageParser<TResponse> parser, GrpcMetadata? metadata = null)
        where TRequest : IMessage<TRequest>
        where TResponse : IMessage<TResponse>
    {
        var reply = await CallRawAsync($"/identity.v1.Identity/{method}", request.ToByteArray(), metadata);
        return parser.ParseFrom(reply);
    }

    /// <summary>Calls any method address with raw bytes — used by the envelope path and negative tests.</summary>
    public Task<byte[]> CallRawAsync(string methodPath, byte[] payload, GrpcMetadata? metadata = null) =>
        InvokeAsync(_channel, methodPath, payload, metadata);

    /// <summary>
    /// Calls the admin surface on whichever port it actually listens on. Management tests go through this
    /// rather than <see cref="CallRawAsync"/> so that they keep working — and keep meaning something —
    /// when the two ports are split.
    /// </summary>
    public Task<byte[]> CallManagementRawAsync(string methodPath, byte[] payload, GrpcMetadata? metadata = null) =>
        InvokeAsync(_managementChannel, methodPath, payload, metadata);

    private static async Task<byte[]> InvokeAsync(
        GrpcChannel channel, string methodPath, byte[] payload, GrpcMetadata? metadata)
    {
        var slash = methodPath.LastIndexOf('/');
        var marshaller = Marshallers.Create(b => (byte[])b, b => b);
        var descriptor = new Method<byte[], byte[]>(
            MethodType.Unary, methodPath[1..slash], methodPath[(slash + 1)..], marshaller, marshaller);

        var options = metadata is null ? new CallOptions() : new CallOptions(metadata);
        return await channel.CreateCallInvoker().AsyncUnaryCall(descriptor, null, options, payload);
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
/// The same stack with the per-IP token throttle turned down to a level a test can actually reach. Its own
/// fixture rather than a knob on the shared one: the limit is read once at boot, and a stack that starts
/// throttled would make every other test in the suite race the bucket.
/// </summary>
public sealed class GrpcThrottledIdentityFixture : GrpcIdentityFixture
{
    /// <summary>Requests one IP may make per minute before Core answers 429.</summary>
    public const int PerIpPerMinute = 3;

    protected override void Tune(RedbIdentityOptions options)
    {
        // C1, the per-IP limiter. It reads redbHttp.RemoteAddress, which over gRPC exists only because
        // the listener is built with EmitHttpCompatHeaders - so this fixture is what proves that bridge
        // carries a real protection rather than a header nobody reads.
        options.RateLimit.Enabled = true;
        options.RateLimit.PerIpPerMinute = PerIpPerMinute;
    }
}

/// <summary>
/// The same stack, reachable from a container. Used by the interop test that drives an independent
/// <c>@grpc/grpc-js</c> client generated from the published <c>identity.v1.proto</c>.
/// </summary>
public sealed class GrpcInteropIdentityFixture : GrpcIdentityFixture
{
    protected override string BindHost => "0.0.0.0";
}

/// <summary>
/// The same stack with the admin surface on a port of its own — the production shape, and the branch of
/// <c>EffectiveManagementPort</c> that no other fixture reaches.
/// </summary>
public sealed class GrpcSplitPortIdentityFixture : GrpcIdentityFixture
{
    private readonly int _managementPort = FreePort();

    protected override int? ManagementPort => _managementPort;

    private static int FreePort()
    {
        var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}

/// <summary>
/// Core wired WITHOUT a management authentication processor, so
/// <c>direct-vm://identity-auth-management</c> is never registered while the gRPC management surface is.
/// A deployment can reach this state, and what happens next is the whole question: an authentication hop
/// pointing at an address nobody serves must refuse, never wave the call through.
/// </summary>
public sealed class GrpcManagementWithoutAuthFixture : GrpcIdentityFixture
{
    protected override bool RegisterManagementAuth => false;
}
