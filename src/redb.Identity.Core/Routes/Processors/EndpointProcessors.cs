using OpenIddict.Server;
using redb.Identity.Core.OpenIddict;
using redb.Route.Abstractions;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// Discovery endpoint (OpenID Connect Configuration).
/// </summary>
internal sealed class DiscoveryEndpointProcessor : IProcessor
{
    private readonly RedbRouteOpenIddictServerHandler _handler;

    public DiscoveryEndpointProcessor(RedbRouteOpenIddictServerHandler handler)
        => _handler = handler;

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        await _handler.ProcessAsync(exchange, OpenIddictServerEndpointType.Configuration, ct);

        // D1/D2: discovery doc is bounded-mutable (claims, scopes, endpoints rarely change).
        // RFC 8414 doesn't mandate a cache header, but RFC 7234 §5.2 says clients SHOULD
        // cache. Five minutes is small enough to roll forward after a config push, large
        // enough to cut request volume on cold-start spikes.
        if (exchange.HasOut)
        {
            exchange.Out!.Headers["Cache-Control"] = "public, max-age=300";
            exchange.Out!.Headers.TryAdd("Vary", "Accept");
        }
    }
}

/// <summary>
/// JWKS endpoint (JSON Web Key Set).
/// </summary>
internal sealed class JwksEndpointProcessor : IProcessor
{
    private readonly RedbRouteOpenIddictServerHandler _handler;

    public JwksEndpointProcessor(RedbRouteOpenIddictServerHandler handler)
        => _handler = handler;

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        await _handler.ProcessAsync(exchange, OpenIddictServerEndpointType.JsonWebKeySet, ct);

        // D2: JWKS rotation overlap — RPs MUST cache (OIDC Core §10.1.1) but a too-long
        // TTL delays detecting a newly-rotated key. One hour matches Microsoft / Google /
        // Auth0 conventions and is well within the typical 24-72h overlap window.
        if (exchange.HasOut)
        {
            exchange.Out!.Headers["Cache-Control"] = "public, max-age=3600";
            exchange.Out!.Headers.TryAdd("Vary", "Accept");
        }
    }
}

/// <summary>
/// Token introspection endpoint (RFC 7662).
/// </summary>
internal sealed class IntrospectionEndpointProcessor : IProcessor
{
    private readonly RedbRouteOpenIddictServerHandler _handler;

    public IntrospectionEndpointProcessor(RedbRouteOpenIddictServerHandler handler)
        => _handler = handler;

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        await _handler.ProcessAsync(exchange, OpenIddictServerEndpointType.Introspection, ct);

        // H6 (RFC 7662): emit audit for every well-formed introspection (not for invalid_request
        // — protocol-level wire errors are noise, not security signals).
        var body = (exchange.HasOut ? exchange.Out!.Body : exchange.In.Body) as IDictionary<string, object?>;
        var isInvalidRequest = body?.TryGetValue("error", out var err) == true
                               && err?.ToString() == "invalid_request";
        if (isInvalidRequest) return;

        var active = body?.TryGetValue("active", out var a) == true && a is bool b && b;
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.TokenIntrospected;
        exchange.Properties["identity-event-data"] = new
        {
            ClientId = exchange.In.GetHeader<string>("client_id"),
            Active = active
        };
    }
}

/// <summary>
/// Token revocation endpoint (RFC 7009).
/// </summary>
internal sealed class RevocationEndpointProcessor : IProcessor
{
    private readonly RedbRouteOpenIddictServerHandler _handler;
    private readonly TimeProvider _timeProvider;

    public RevocationEndpointProcessor(RedbRouteOpenIddictServerHandler handler, TimeProvider? timeProvider = null)
    {
        _handler = handler;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        await _handler.ProcessAsync(exchange, OpenIddictServerEndpointType.Revocation, ct);

        // Only suppress TokenRevoked event for malformed requests (e.g. missing token parameter).
        // Per RFC 7009, the server SHOULD return 200 even for invalid/unknown tokens,
        // so we fire the event for all well-formed requests.
        var body = (exchange.HasOut ? exchange.Out!.Body : exchange.In.Body) as IDictionary<string, object?>;
        var isInvalidRequest = body?.TryGetValue("error", out var err) == true
                               && err?.ToString() == "invalid_request";

        if (!isInvalidRequest)
        {
            exchange.Properties["identity-event-type"] = IdentityAuditEventIds.TokenRevoked;
            exchange.Properties["identity-event-data"] = new
            {
                ClientId = exchange.In.GetHeader<string>("client_id"),
                Timestamp = _timeProvider.GetUtcNow()
            };
        }
    }
}

/// <summary>
/// Pushed Authorization Request endpoint (RFC 9126 / Z6). The caller pushes the
/// authorization parameters (client_id, redirect_uri, scope, state, code_challenge,
/// …) over a back-channel POST to <c>/connect/par</c> and receives a one-time
/// <c>request_uri</c> to be included on the next user-agent redirect to <c>/connect/authorize</c>.
/// All validation — client auth, PKCE, scope, redirect_uri — is handled by OpenIddict.
/// </summary>
internal sealed class PushedAuthorizationEndpointProcessor : IProcessor
{
    private readonly RedbRouteOpenIddictServerHandler _handler;

    public PushedAuthorizationEndpointProcessor(RedbRouteOpenIddictServerHandler handler)
        => _handler = handler;

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        await _handler.ProcessAsync(exchange, OpenIddictServerEndpointType.PushedAuthorization, ct);

        // Audit: success when body contains request_uri (per RFC 9126 §2.2),
        // failure when body contains "error".
        var body = (exchange.HasOut ? exchange.Out!.Body : exchange.In.Body) as IDictionary<string, object?>;
        if (body is null) return;

        if (body.ContainsKey("request_uri"))
        {
            exchange.Properties["identity-event-type"] = redb.Identity.Contracts.Routes.IdentityAuditEventIds.ParRequestAccepted;
            exchange.Properties["identity-event-data"] = new
            {
                ClientId = exchange.In.GetHeader<string>("client_id"),
            };
        }
        else if (body.TryGetValue("error", out var err))
        {
            exchange.Properties["identity-event-type"] = redb.Identity.Contracts.Routes.IdentityAuditEventIds.ParRequestRejected;
            exchange.Properties["identity-event-data"] = new
            {
                ClientId = exchange.In.GetHeader<string>("client_id"),
                Error = err?.ToString()
            };
        }
    }
}

/// <summary>
/// Device authorization endpoint (RFC 8628).
/// </summary>
internal sealed class DeviceEndpointProcessor : IProcessor
{
    private readonly RedbRouteOpenIddictServerHandler _handler;

    public DeviceEndpointProcessor(RedbRouteOpenIddictServerHandler handler)
        => _handler = handler;

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        await _handler.ProcessAsync(exchange, OpenIddictServerEndpointType.DeviceAuthorization, ct);

        // H7 (RFC 8628): emit DeviceCodeIssued only on success (presence of device_code in body).
        var body = (exchange.HasOut ? exchange.Out!.Body : exchange.In.Body) as IDictionary<string, object?>;
        if (body?.ContainsKey("device_code") == true)
        {
            exchange.Properties["identity-event-type"] = IdentityAuditEventIds.DeviceCodeIssued;
            exchange.Properties["identity-event-data"] = new
            {
                ClientId = exchange.In.GetHeader<string>("client_id"),
            };
        }
    }
}

/// <summary>
/// End-user verification endpoint (RFC 8628 §3.3).
/// The user enters the user_code and authenticates to approve the device.
/// </summary>
internal sealed class VerificationEndpointProcessor : IProcessor
{
    private readonly RedbRouteOpenIddictServerHandler _handler;

    public VerificationEndpointProcessor(RedbRouteOpenIddictServerHandler handler)
        => _handler = handler;

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        await _handler.ProcessAsync(exchange, OpenIddictServerEndpointType.EndUserVerification, ct);

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.DeviceCodeVerified;
    }
}
