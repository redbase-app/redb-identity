using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Extracts the authorization request parameters from <see cref="IExchange.In"/>.
/// </summary>
internal sealed class ExtractAuthorizationRequestHandler
    : IOpenIddictServerHandler<ExtractAuthorizationRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractAuthorizationRequestContext>()
            .UseSingletonHandler<ExtractAuthorizationRequestHandler>()
            .SetOrder(int.MinValue + 50_000)
            .Build();

    public ValueTask HandleAsync(ExtractAuthorizationRequestContext context)
    {
        var exchange = context.Transaction.GetRouteExchange();
        if (exchange is null)
            return default;

        context.Request = RedbRouteOpenIddictServerHelpers.CreateRequestFromExchange(exchange);
        return default;
    }
}
