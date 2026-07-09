using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Extracts the Pushed Authorization Request parameters (RFC 9126) from
/// <see cref="IExchange.In"/> — same form-body shape as the Token endpoint.
/// </summary>
internal sealed class ExtractPushedAuthorizationRequestHandler
    : IOpenIddictServerHandler<ExtractPushedAuthorizationRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractPushedAuthorizationRequestContext>()
            .UseSingletonHandler<ExtractPushedAuthorizationRequestHandler>()
            .SetOrder(int.MinValue + 50_000)
            .Build();

    public ValueTask HandleAsync(ExtractPushedAuthorizationRequestContext context)
    {
        var exchange = context.Transaction.GetRouteExchange();
        if (exchange is null)
            return default;

        context.Request = RedbRouteOpenIddictServerHelpers.CreateRequestFromExchange(exchange);
        return default;
    }
}
