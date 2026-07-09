using OpenIddict.Server;
using redb.Identity.Core.OpenIddict;
using redb.Route.Abstractions;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// Token endpoint processor. Delegates to the OpenIddict pipeline via
/// <see cref="RedbRouteOpenIddictServerHandler.ProcessAsync"/>.
/// </summary>
internal sealed class TokenEndpointProcessor : IProcessor
{
    private readonly RedbRouteOpenIddictServerHandler _handler;
    private readonly TimeProvider _timeProvider;

    public TokenEndpointProcessor(RedbRouteOpenIddictServerHandler handler, TimeProvider? timeProvider = null)
    {
        _handler = handler;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        await _handler.ProcessAsync(exchange, OpenIddictServerEndpointType.Token, ct);

        // Only emit event if token issuance succeeded (no error in response)
        var body = exchange.Out?.Body;
        if (body is Dictionary<string, object?> dict && dict.ContainsKey("error"))
            return;

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.TokenIssued;
        exchange.Properties["identity-event-data"] = new
        {
            ClientId = exchange.In.GetHeader<string>("client_id"),
            GrantType = exchange.In.GetHeader<string>("grant_type"),
            Timestamp = _timeProvider.GetUtcNow()
        };
    }
}

/// <summary>
/// Authorization endpoint processor. Delegates to the OpenIddict pipeline.
/// </summary>
internal sealed class AuthorizeEndpointProcessor : IProcessor
{
    private readonly RedbRouteOpenIddictServerHandler _handler;

    public AuthorizeEndpointProcessor(RedbRouteOpenIddictServerHandler handler)
        => _handler = handler;

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        await _handler.ProcessAsync(exchange, OpenIddictServerEndpointType.Authorization, ct);

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.AuthorizationGranted;
    }
}

/// <summary>
/// Userinfo endpoint processor. Delegates to the OpenIddict pipeline.
/// </summary>
internal sealed class UserinfoEndpointProcessor : IProcessor
{
    private readonly RedbRouteOpenIddictServerHandler _handler;

    public UserinfoEndpointProcessor(RedbRouteOpenIddictServerHandler handler)
        => _handler = handler;

    public Task Process(IExchange exchange, CancellationToken ct = default)
        => _handler.ProcessAsync(exchange, OpenIddictServerEndpointType.UserInfo, ct);
}
