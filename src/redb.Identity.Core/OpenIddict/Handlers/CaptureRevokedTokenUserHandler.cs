using OpenIddict.Server;
using redb.Identity.Core.Services;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Hands the internal user id of a token revoked at the revocation endpoint (RFC 7009) to the route
/// exchange, so the <c>TokenRevoked</c> audit event names the user (<c>RevocationEndpointProcessor</c>).
/// A subscriber that caches token checks per user (a resource server introspecting in process, for
/// one) then drops only that user's entries instead of all of them.
/// <para>
/// Only for user grants: a client-credentials token has no <c>redb:user_id</c>, and an unknown or
/// invalid token has no principal; the event then carries no user, as before.
/// </para>
/// </summary>
internal sealed class CaptureRevokedTokenUserHandler : IOpenIddictServerHandler<HandleRevocationRequestContext>
{
    /// <summary>The exchange property the internal user id is put in.</summary>
    public const string ExchangeProperty = "identity:revoked-user-id";

    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleRevocationRequestContext>()
            .UseSingletonHandler<CaptureRevokedTokenUserHandler>()
            .SetOrder(int.MaxValue - 1000)
            .Build();

    public ValueTask HandleAsync(HandleRevocationRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var userId = context.GenericTokenPrincipal?.FindFirst(IdentityPrincipalBuilder.InternalUserIdClaim)?.Value;
        if (!string.IsNullOrEmpty(userId) && context.Transaction.GetRouteExchange() is { } exchange)
            exchange.Properties[ExchangeProperty] = userId;

        return default;
    }
}
