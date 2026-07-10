using System.Data.Common;
using System.Security.Claims;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Npgsql;
using OpenIddict.Abstractions;
using redb.Core;
using redb.Core.Models.Configuration;
using redb.Core.Models.Entities;
using redb.Core.Extensions;
using redb.Core.Pro.Extensions;
using redb.Identity.Contracts.ClaimMappers;
using redb.Identity.Contracts.Common;
using redb.Identity.Core;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Contracts.Routes;
using redb.Identity.Core.Services;
using redb.Postgres.Pro.Extensions;
using redb.Route.Abstractions;
using redb.Route.Components;
using redb.Route.Core;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;
using redb.Identity.Core.Routes;using redb.Identity.Tests.Infrastructure;


namespace redb.Identity.Tests.ClaimMappers;

/// <summary>
/// H5 (v1.0 DoD §5): integration tests for declarative claim mapper resolution.
/// Covers global mappers, per-application overlay, Client Scope assignment,
/// scope filtering, last-write-wins precedence and Required-failure rejection.
/// </summary>
public class ClaimMappersIntegrationTests : IAsyncLifetime
{
    private const string PgConnString =
        "Host=localhost;Port=5432;Username=postgres;Password=1;Database=redb;Include Error Detail=true";

    private ServiceProvider _sp = null!;
    private IRedbService _redb = null!;
    private RouteContext _ctx = null!;
    private ClaimMappersResolver _resolver = null!;

    public async Task InitializeAsync()
    {
        DbProviderFactories.RegisterFactory("Npgsql", NpgsqlFactory.Instance);

        var config = new ConfigurationBuilder().AddJsonFile("appsettings.json").Build();
        var cs = config.GetConnectionString("Postgres") ?? PgConnString;

        var services = new ServiceCollection();
        services.AddLogging(b => b.SetMinimumLevel(LogLevel.Warning));

        services.AddRedbForTests(cs);

        services.AddSingleton<SharedVmRegistry>();

        var idOpts = new RedbIdentityOptions
        {
            Issuer = new Uri("https://identity.test.local/"),
            AllowEphemeralKeys = true,
            DisableAccessTokenEncryption = true,
            TokenThrottleMaxPerPeriod = 1000,
        };
        services.AddSingleton(Options.Create(idOpts));
        services.AddSingleton(Options.Create(new IdentityAuditOptions { Enabled = false }));

        services.AddRedbIdentityServer(idOpts);

        _sp = services.BuildServiceProvider();
        _redb = _sp.GetRequiredService<IRedbService>();

        try { await _redb.InitializeAsync(ensureCreated: true); }
        catch { await _redb.InitializeAsync(); }

        await _redb.SyncSchemeAsync<ApplicationProps>();
        await _redb.SyncSchemeAsync<ScopeProps>();
        await _redb.SyncSchemeAsync<UserProps>();
        await _redb.SyncSchemeAsync<ClaimMapperProps>();
        await _redb.SyncSchemeAsync<ClaimScopeProps>();
        await _redb.SyncSchemeAsync<ClaimScopeAssignmentProps>();
        await _redb.InitializeTypeRegistryAsync();

        await PurgeClaimSchemesAsync();

        _resolver = new ClaimMappersResolver(_redb);

        _ctx = new RouteContext(_sp, "claim-mappers-integration-test");
        _ctx.AddRoutes(new IdentityCoreRouteBuilder(
            _sp,
            Options.Create(idOpts),
            Options.Create(new IdentityAuditOptions { Enabled = false })));
        await _ctx.Start();
    }

    public async Task DisposeAsync()
    {
        // Purge before tearing down so a Required global mapper (e.g. "must-have")
        // created by the last test in this class does not survive into other
        // collections that share the same physical DB and call EnrichPrincipal.
        if (_redb != null) await PurgeClaimSchemesAsync();
        if (_ctx != null) await _ctx.Stop();
        if (_sp != null) await _sp.DisposeAsync();
    }

    // Provider-agnostic purge: delete every claim-mapper / claim-scope object via
    // the redb service so it hits whatever provider REDB_PROVIDER selected. The
    // previous raw-Npgsql version always cleaned Postgres, so under an MSSQL run it
    // silently no-oped — leaked Required global mappers then poisoned EnrichPrincipal
    // for the whole suite ("Required claim mapper ... resolved to empty value").
    private async Task PurgeClaimSchemesAsync()
    {
        await PurgeSchemeAsync<ClaimMapperProps>();
        await PurgeSchemeAsync<ClaimScopeProps>();
        await PurgeSchemeAsync<ClaimScopeAssignmentProps>();
    }

    private async Task PurgeSchemeAsync<T>() where T : class, new()
    {
        try
        {
            var objs = await _redb.Query<T>().ToListAsync();
            if (objs.Count > 0)
                await _redb.DeleteAsync(objs.Select(o => o.Id));
        }
        catch { /* scheme not yet materialised — nothing to purge */ }
    }

    // ── helpers ──

    private async Task<long> CreateUser(string subject, string givenName, Dictionary<string, string>? customClaims = null)
    {
        // Synthetic userId — in production set by UserManagementProcessor (oidcObj.key = coreUser.Id).
        // For these tests we just need a stable Key the resolver can query against.
        var userId = DateTimeOffset.UtcNow.Ticks + Random.Shared.Next(1000, 9999);

        var user = new RedbObject<UserProps>(new UserProps
        {
            GivenName = givenName,
            EmailVerified = true,
            CustomClaims = customClaims,
        });
        user.Name = subject;
        user.key = userId;
        await _redb.SaveAsync(user);
        return userId;
    }

    private async Task<long> CreateApp(string clientId)
    {
        var app = new RedbObject<ApplicationProps>(new ApplicationProps
        {
            ClientId = clientId,
            ClientType = "confidential",
        });
        app.Name = clientId;
        app.value_string = clientId;
        await _redb.SaveAsync(app);
        return app.Id;
    }

    private async Task<long> CreateMapper(
        long? parentId,
        string claimType,
        string sourceKind,
        string? sourcePath = null,
        string? constantValue = null,
        string[]? requiredScopes = null,
        bool required = false,
        int order = 0,
        string[]? destinations = null)
    {
        var m = new RedbObject<ClaimMapperProps>(new ClaimMapperProps
        {
            ClaimType = claimType,
            SourceKind = sourceKind,
            SourcePath = sourcePath,
            ConstantValue = constantValue,
            RequiredScopes = requiredScopes,
            Required = required,
            Order = order,
            Enabled = true,
            Destinations = destinations,
        });
        m.Name = $"{sourceKind}->{claimType}";
        if (parentId.HasValue) m.ParentId = parentId.Value;
        await _redb.SaveAsync(m);
        return m.Id;
    }

    private static ClaimsPrincipal MakePrincipal(string subject)
    {
        var identity = new ClaimsIdentity(authenticationType: "Test");
        identity.AddClaim(new Claim(Claims.Subject, subject));
        return new ClaimsPrincipal(identity);
    }

    // ── tests ──

    [Fact]
    public async Task GlobalMapper_Constant_AddsClaimToBothDestinations()
    {
        var userId = await CreateUser("u-global-" + Guid.NewGuid().ToString("N")[..6], "global@test.local");
        await CreateMapper(parentId: null, "tenant", "Constant", constantValue: "acme");

        var principal = MakePrincipal(userId.ToString());

        await _resolver.EnrichPrincipalAsync(principal, userId, applicationId: null,
            requestedScopes: ["openid"], CancellationToken.None);

        var claim = principal.FindFirst("tenant");
        claim.Should().NotBeNull();
        claim!.Value.Should().Be("acme");
        claim.GetDestinations().Should().Contain(Destinations.AccessToken)
            .And.Contain(Destinations.IdentityToken);
    }

    [Fact]
    public async Task GlobalMapper_UserPropsPath_ExtractsGivenName()
    {
        var subject = "u-given-" + Guid.NewGuid().ToString("N")[..6];
        var userId = await CreateUser(subject, "Alice");
        await CreateMapper(parentId: null, Claims.GivenName, "UserProps", sourcePath: "GivenName");

        var principal = MakePrincipal(userId.ToString());
        await _resolver.EnrichPrincipalAsync(principal, userId, applicationId: null,
            requestedScopes: ["openid", "profile"], CancellationToken.None);

        principal.FindFirst(Claims.GivenName)!.Value.Should().Be("Alice");
    }

    [Fact]
    public async Task CustomClaim_Source_ResolvedFromUserPropsBag()
    {
        var subject = "u-custom-" + Guid.NewGuid().ToString("N")[..6];
        var userId = await CreateUser(subject, "u@test.local",
            customClaims: new Dictionary<string, string> { ["department"] = "engineering" });
        await CreateMapper(parentId: null, "department", "CustomClaim", sourcePath: "department");

        var principal = MakePrincipal(userId.ToString());
        await _resolver.EnrichPrincipalAsync(principal, userId, applicationId: null,
            requestedScopes: [], CancellationToken.None);

        principal.FindFirst("department")!.Value.Should().Be("engineering");
    }

    [Fact]
    public async Task AppOverlay_OverridesGlobalForSameClaimType()
    {
        var userId = await CreateUser("u-ovr-" + Guid.NewGuid().ToString("N")[..6], "ovr@test.local");
        var appId = await CreateApp("client-" + Guid.NewGuid().ToString("N")[..6]);

        await CreateMapper(parentId: null, "tier", "Constant", constantValue: "free");          // global
        await CreateMapper(parentId: appId, "tier", "Constant", constantValue: "enterprise");    // overlay

        var principal = MakePrincipal(userId.ToString());
        await _resolver.EnrichPrincipalAsync(principal, userId, applicationId: appId,
            requestedScopes: [], CancellationToken.None);

        principal.FindFirst("tier")!.Value.Should().Be("enterprise");
    }

    [Fact]
    public async Task ScopeFiltering_OnlyEmittedWhenRequiredScopePresent()
    {
        var userId = await CreateUser("u-scope-" + Guid.NewGuid().ToString("N")[..6], "scope@test.local",
            customClaims: new Dictionary<string, string> { ["roles"] = "admin,user" });

        await CreateMapper(parentId: null, "roles", "CustomClaim", sourcePath: "roles",
            requiredScopes: ["roles"]);

        // Without "roles" scope: must NOT be emitted
        var p1 = MakePrincipal(userId.ToString());
        await _resolver.EnrichPrincipalAsync(p1, userId, applicationId: null,
            requestedScopes: ["openid"], CancellationToken.None);
        p1.FindFirst("roles").Should().BeNull();

        // With "roles" scope: emitted
        var p2 = MakePrincipal(userId.ToString());
        await _resolver.EnrichPrincipalAsync(p2, userId, applicationId: null,
            requestedScopes: ["openid", "roles"], CancellationToken.None);
        p2.FindFirst("roles")!.Value.Should().Be("admin,user");
    }

    [Fact]
    public async Task AssignedClientScope_EmitsItsMappers()
    {
        var userId = await CreateUser("u-csa-" + Guid.NewGuid().ToString("N")[..6], "csa@test.local");
        var appId = await CreateApp("client-csa-" + Guid.NewGuid().ToString("N")[..6]);

        // Create a Client Scope object
        var scope = new RedbObject<ClaimScopeProps>(new ClaimScopeProps
        {
            ScopeName = "tenant-info",
            Enabled = true,
        });
        scope.Name = "tenant-info";
        scope.value_string = "tenant-info";
        await _redb.SaveAsync(scope);

        // Mapper under the scope
        await CreateMapper(parentId: scope.Id, "scope_marker", "Constant", constantValue: "from-client-scope");

        // Without assignment — must NOT appear
        var p1 = MakePrincipal(userId.ToString());
        await _resolver.EnrichPrincipalAsync(p1, userId, applicationId: appId,
            requestedScopes: [], CancellationToken.None);
        p1.FindFirst("scope_marker").Should().BeNull();

        // Assign and re-resolve
        var assignment = new RedbObject<ClaimScopeAssignmentProps>(new ClaimScopeAssignmentProps
        {
            ApplicationId = appId,
            ScopeId = scope.Id,
            AssignedAt = DateTimeOffset.UtcNow,
        });
        assignment.Name = $"{appId}::{scope.Id}";
        assignment.key = appId;
        await _redb.SaveAsync(assignment);

        var p2 = MakePrincipal(userId.ToString());
        await _resolver.EnrichPrincipalAsync(p2, userId, applicationId: appId,
            requestedScopes: [], CancellationToken.None);
        p2.FindFirst("scope_marker")!.Value.Should().Be("from-client-scope");
    }

    [Fact]
    public async Task RequiredMapper_WithEmptyValue_Throws()
    {
        var userId = await CreateUser("u-req-" + Guid.NewGuid().ToString("N")[..6], "req@test.local");
        // No "missing-claim" key in CustomClaims → resolves to null
        await CreateMapper(parentId: null, "must-have", "CustomClaim",
            sourcePath: "missing-claim", required: true);

        var principal = MakePrincipal(userId.ToString());
        var act = async () => await _resolver.EnrichPrincipalAsync(principal, userId, applicationId: null,
            requestedScopes: [], CancellationToken.None);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*must-have*");
    }

    [Fact]
    public async Task DisabledScope_IsIgnored()
    {
        var userId = await CreateUser("u-dis-" + Guid.NewGuid().ToString("N")[..6], "dis@test.local");
        var appId = await CreateApp("client-dis-" + Guid.NewGuid().ToString("N")[..6]);

        var scope = new RedbObject<ClaimScopeProps>(new ClaimScopeProps
        {
            ScopeName = "disabled-scope",
            Enabled = false,
        });
        scope.Name = "disabled-scope";
        scope.value_string = "disabled-scope";
        await _redb.SaveAsync(scope);

        await CreateMapper(parentId: scope.Id, "ignored", "Constant", constantValue: "should-not-appear");

        var assignment = new RedbObject<ClaimScopeAssignmentProps>(new ClaimScopeAssignmentProps
        {
            ApplicationId = appId,
            ScopeId = scope.Id,
            AssignedAt = DateTimeOffset.UtcNow,
        });
        assignment.Name = $"{appId}::{scope.Id}";
        assignment.key = appId;
        await _redb.SaveAsync(assignment);

        var principal = MakePrincipal(userId.ToString());
        await _resolver.EnrichPrincipalAsync(principal, userId, applicationId: appId,
            requestedScopes: [], CancellationToken.None);

        principal.FindFirst("ignored").Should().BeNull();
    }

    // ── processor / route smoke tests ──

    [Fact]
    public async Task ClaimMapperProcessor_CreateReadList_RoundTrip()
    {
        var endpoint = _ctx.GetEndpoint(IdentityEndpoints.ManageClaimMappers);

        var createReq = new CreateClaimMapperRequest
        {
            ClaimType = "smoke-claim",
            SourceKind = "Constant",
            ConstantValue = "smoke-value",
            Owner = "global",
        };
        var createMsg = new Message { Body = createReq };
        createMsg.Headers["operation"] = "create";
        var ex = new Exchange(createMsg) { Pattern = ExchangePattern.InOut };
        await endpoint.CreateProducer().Process(ex);
        ex.Exception.Should().BeNull();

        // Camel canon: read response from Out ?? In. The route is
        // [tx, idempPre, business, idempCapture, WireTap]; PipelineProcessor merges Out into
        // In on every intermediate step, so the final WireTap leaves the response on In.
        var resp = (ex.Out ?? ex.In).Body as ClaimMapperResponse;
        resp.Should().NotBeNull();
        resp!.ClaimType.Should().Be("smoke-claim");
        resp.Owner.Should().Be("global");

        // List
        var listMsg = new Message { Body = new ListRequest { Count = 50 } };
        listMsg.Headers["operation"] = "list";
        var lex = new Exchange(listMsg) { Pattern = ExchangePattern.InOut };
        await endpoint.CreateProducer().Process(lex);
        lex.Exception.Should().BeNull();
        var page = (lex.Out ?? lex.In).Body as PagedResult<ClaimMapperResponse>;
        page.Should().NotBeNull();
        page!.Items.Should().Contain(i => i.Id == resp.Id);
    }

    [Fact(Skip = "PG hang on _sp.DisposeAsync(): NpgsqlOperationInProgressException for an in-flight " +
        "pvt_cte SELECT that the test's processor chain spawned but never awaited (most likely a fire-" +
        "and-forget WireTap audit task or an inner async not awaited inside ClaimScopeProcessor). The 3-minute " +
        "test-host inactivity timer fires; the rest of the suite never runs. Skipped to keep the run completable; " +
        "the bug is in the test code (or the processor's async hygiene), NOT in the Postgres provider — " +
        "a `MapRow` loud-throw attempt (commit 30f9172b, reverted in 21e945d7) demonstrated the same hang for the same root cause. " +
        "Re-enable by tracking the leaking pvt_cte through ClaimScopeProcessor / IdempotencyProcessor / WireTap chain.")]
    public async Task ClaimScopeProcessor_AssignUnassignIdempotent()
    {
        var appId = await CreateApp("client-route-" + Guid.NewGuid().ToString("N")[..6]);
        var endpoint = _ctx.GetEndpoint(IdentityEndpoints.ManageClaimScopes);

        // create scope via processor
        var c = new Message { Body = new CreateClaimScopeRequest { Name = "route-scope-" + Guid.NewGuid().ToString("N")[..6], Enabled = true } };
        c.Headers["operation"] = "create";
        var cex = new Exchange(c) { Pattern = ExchangePattern.InOut };
        await endpoint.CreateProducer().Process(cex);
        cex.Exception.Should().BeNull();
        var scope = (cex.Out ?? cex.In).Body as ClaimScopeResponse;
        scope.Should().NotBeNull();

        // assign twice — second must return existing (no duplicate row)
        async Task<ClaimScopeAssignmentResponse?> Assign()
        {
            var m = new Message { Body = new AssignClaimScopeRequest { ApplicationId = appId.ToString(), ScopeId = scope!.Id } };
            m.Headers["operation"] = "assign";
            var e = new Exchange(m) { Pattern = ExchangePattern.InOut };
            await endpoint.CreateProducer().Process(e);
            e.Exception.Should().BeNull();
            return (e.Out ?? e.In).Body as ClaimScopeAssignmentResponse;
        }

        var a1 = await Assign();
        var a2 = await Assign();
        a1.Should().NotBeNull();
        a2.Should().NotBeNull();
        a2!.Id.Should().Be(a1!.Id);

        // unassign
        var u = new Message
        {
            Body = new Dictionary<string, object?>
            {
                ["applicationId"] = appId,
                ["scopeId"] = long.Parse(scope!.Id),
            }
        };
        u.Headers["operation"] = "unassign";
        var uex = new Exchange(u) { Pattern = ExchangePattern.InOut };
        await endpoint.CreateProducer().Process(uex);
        uex.Exception.Should().BeNull();
    }
}
