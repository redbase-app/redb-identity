using Microsoft.Extensions.Options;
using redb.Identity.Contracts.Routes;
using redb.Identity.Grpc.Processors;
using redb.Identity.Management.Controllers;
using redb.Route.Controllers;
using redb.Route.Controllers.Extensions;
using redb.Route.Core;
using redb.Route.Grpc;

namespace redb.Identity.Grpc;

/// <summary>
/// F6 — the management surface over gRPC. One method address per controller action, on the management
/// port, behind bearer authentication and the granular scope table in Core.
/// <para>
/// Separate from <see cref="GrpcFacadeRouteBuilder"/> because the two surfaces are separate in every way
/// that matters operationally: the protocol surface is called by every relying party, the management
/// surface only by admin tooling. Different consumers, different blast radius, and — when
/// <c>ManagementPort</c> is set — a different port to firewall.
/// </para>
/// <para>
/// The chain is the same for every operation, and its order is the security property: name the call,
/// decode it, authenticate, halt if refused, authorize, halt if refused, only then dispatch. Both gates
/// run on isolated exchanges, so the halt is explicit rather than inherited from Core's
/// <c>exchange.Stop()</c> — see <see cref="GrpcManagementProcessors.RequireAuthorized"/>.
/// </para>
/// </summary>
public class GrpcManagementRouteBuilder : RouteBuilder
{
    private readonly IdentityGrpcTransportOptions _options;

    public GrpcManagementRouteBuilder(IOptions<IdentityGrpcTransportOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options.Value;
    }

    private const string Package = "/identity.management.v1";

    /// <summary>
    /// Canonical resource identifiers — the same strings the HTTP facade passes, because Core's scope
    /// table is keyed on them. A wrong one here does not fail loudly: it checks another surface's scopes,
    /// or falls through to default-deny. They are constants for that reason.
    /// </summary>
    private const string UsersResource = "/api/v1/identity/users";
    private const string ApplicationsResource = "/api/v1/identity/applications";
    private const string GroupsResource = "/api/v1/identity/groups";
    private const string ScopesResource = "/api/v1/identity/scopes";
    private const string TokensResource = "/api/v1/identity/tokens";

    /// <summary>
    /// The five groups the plan named: 40 operations. Read or write is taken from the controller's own
    /// HTTP verb, so the two transports cannot disagree about what mutates; the resource is the surface,
    /// so Core's scope table sees exactly what it sees for HTTP.
    /// <para>
    /// Dispatch names are qualified (<c>Users.List</c>) and must stay that way: five controllers now share
    /// method names like <c>List</c> and <c>Delete</c>, and an unqualified name resolves to whichever
    /// matched first.
    /// </para>
    /// <para>
    /// Self-service (<c>/me</c>, account, password recovery, MFA enrolment) is deliberately absent. Those
    /// are end-user flows reached from a browser or an app session, not admin tooling, and putting them on
    /// an admin port would widen that port's blast radius for no caller that exists.
    /// </para>
    /// </summary>
    private static readonly ManagementOperation[] Operations =
    [
        new("Users", "List", "Users.List", UsersResource, Writes: false),
        new("Users", "Search", "Users.Search", UsersResource, Writes: false),
        new("Users", "Get", "Users.Get", UsersResource, Writes: false),
        new("Users", "Create", "Users.Create", UsersResource, Writes: true),
        new("Users", "Update", "Users.Update", UsersResource, Writes: true),
        new("Users", "Delete", "Users.Delete", UsersResource, Writes: true),
        new("Users", "ChangePassword", "Users.ChangePassword", UsersResource, Writes: true),
        new("Users", "AdminResetPassword", "Users.AdminResetPassword", UsersResource, Writes: true),

        new("Applications", "List", "Applications.List", ApplicationsResource, Writes: false),
        new("Applications", "Get", "Applications.Get", ApplicationsResource, Writes: false),
        new("Applications", "Create", "Applications.Create", ApplicationsResource, Writes: true),
        new("Applications", "Update", "Applications.Update", ApplicationsResource, Writes: true),
        new("Applications", "RotateSecret", "Applications.RotateSecret", ApplicationsResource, Writes: true),
        new("Applications", "Delete", "Applications.Delete", ApplicationsResource, Writes: true),

        new("Groups", "List", "Groups.List", GroupsResource, Writes: false),
        new("Groups", "Search", "Groups.Search", GroupsResource, Writes: false),
        new("Groups", "Get", "Groups.Get", GroupsResource, Writes: false),
        new("Groups", "Create", "Groups.Create", GroupsResource, Writes: true),
        new("Groups", "CreateChild", "Groups.CreateChild", GroupsResource, Writes: true),
        new("Groups", "Update", "Groups.Update", GroupsResource, Writes: true),
        new("Groups", "Delete", "Groups.Delete", GroupsResource, Writes: true),
        new("Groups", "Move", "Groups.Move", GroupsResource, Writes: true),
        new("Groups", "Tree", "Groups.Tree", GroupsResource, Writes: false),
        new("Groups", "Path", "Groups.Path", GroupsResource, Writes: false),
        new("Groups", "Children", "Groups.Children", GroupsResource, Writes: false),
        new("Groups", "ListMembers", "Groups.ListMembers", GroupsResource, Writes: false),
        new("Groups", "AddMember", "Groups.AddMember", GroupsResource, Writes: true),
        new("Groups", "UpdateMember", "Groups.UpdateMember", GroupsResource, Writes: true),
        new("Groups", "RemoveMember", "Groups.RemoveMember", GroupsResource, Writes: true),
        new("Groups", "UserGroups", "Groups.UserGroups", GroupsResource, Writes: false),
        new("Groups", "IsMember", "Groups.IsMember", GroupsResource, Writes: false),

        new("Scopes", "List", "Scopes.List", ScopesResource, Writes: false),
        new("Scopes", "Get", "Scopes.Get", ScopesResource, Writes: false),
        new("Scopes", "Create", "Scopes.Create", ScopesResource, Writes: true),
        new("Scopes", "Update", "Scopes.Update", ScopesResource, Writes: true),
        new("Scopes", "Delete", "Scopes.Delete", ScopesResource, Writes: true),

        new("Tokens", "List", "Tokens.List", TokensResource, Writes: false),
        new("Tokens", "Revoke", "Tokens.Revoke", TokensResource, Writes: true),
        new("Tokens", "RevokeBySubject", "Tokens.RevokeBySubject", TokensResource, Writes: true),
        new("Tokens", "Prune", "Tokens.Prune", TokensResource, Writes: true),
    ];

    protected override void Configure()
    {
        var registry = new ControllerRegistry();
        registry.RegisterController(typeof(UsersController));
        registry.RegisterController(typeof(ApplicationsController));
        registry.RegisterController(typeof(GroupsController));
        registry.RegisterController(typeof(ScopesController));
        registry.RegisterController(typeof(TokensController));

        var port = _options.Grpc.EffectiveManagementPort;

        foreach (var operation in Operations)
        {
            From(BuildListener(port).Method($"{Package}.{operation.Service}/{operation.Method}"))
                .RouteId($"grpc-identity-manage-{operation.DispatchMethod.Replace('.', '-').ToLowerInvariant()}")
                .Process(GrpcIdentityProcessors.PropagateCorrelationId)
                .Process(GrpcManagementProcessors.Describe(operation))
                .Process(GrpcManagementProcessors.MapRequest)
                // Authentication: validates the bearer token and leaves identity:management-* behind.
                .Enrich(IdentityEndpoints.AuthManagement, GrpcManagementProcessors.AdoptGateDecision)
                .Process(GrpcManagementProcessors.RequireAuthenticated)
                // Authorization: the granular scope table, shared with the HTTP facade.
                .Enrich(IdentityEndpoints.AuthzCheck, GrpcManagementProcessors.AdoptGateDecision)
                .Process(GrpcManagementProcessors.RequireAuthorized)
                .RedbGrpcController(registry)
                .Process(GrpcManagementProcessors.MapControllerErrorToGrpcStatus)
                .Process(GrpcManagementProcessors.MapResponse);
        }
    }

    /// <summary>
    /// Builds the management listener. Health is mounted here too: the probe answers «is <i>this</i>
    /// listener serving», and when the management port is split off, the protocol port's probe says
    /// nothing about it.
    /// </summary>
    /// <summary>Registry key for the TLS material, kept out of the endpoint URI on purpose.</summary>
    private const string TlsFactoryName = "identity-grpc-management-tls";

    private GrpcBuilder BuildListener(int port)
    {
        var grpc = _options.Grpc;

        var builder = GrpcDsl.Listen($"{grpc.Host}:{port}")
            .MaxMessageSize(grpc.MaxMessageSize)
            .Health(grpc.Health)
            // Core keys its per-IP throttle and brute-force lockout on redbHttp.RemoteAddress, and those
            // checks no-op when the header is absent rather than failing loudly.
            .EmitHttpCompatHeaders(grpc.EmitHttpCompatHeaders);

        if (!string.IsNullOrWhiteSpace(grpc.Compression)
            && Enum.TryParse<GrpcCompression>(grpc.Compression, ignoreCase: true, out var compression))
        {
            builder = builder.Compression(compression);
        }

        if (grpc.Ssl)
        {
            builder = builder.Ssl();

            // Same as the protocol listener: TLS material through a named factory, so the secret is
            // never part of the route key. See GrpcFacadeRouteBuilder for the reasoning.
            Context!.AddToRegistry(TlsFactoryName, new GrpcConnectionFactory
            {
                Ssl = true,
                SslCertPath = grpc.SslCertPath,
                SslCertPassword = grpc.SslCertPassword,
            });
            builder = builder.ConnectionFactory(TlsFactoryName);

            // mTLS is opt-in everywhere, and recommended here: this is the admin surface.
            if (Enum.TryParse<GrpcClientCertificateMode>(grpc.ClientCertificateMode, ignoreCase: true, out var mode)
                && mode != GrpcClientCertificateMode.NoCertificate)
            {
                var thumbprints = (grpc.AllowedClientThumbprints ?? string.Empty)
                    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                builder = builder.ClientCertificates(mode, thumbprints);
            }
        }
        else
        {
            builder = builder.Plaintext();
        }

        return builder;
    }
}
