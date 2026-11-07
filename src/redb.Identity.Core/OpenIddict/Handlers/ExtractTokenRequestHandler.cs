using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Extracts the token request parameters from <see cref="IExchange.In"/>.
/// </summary>
internal sealed class ExtractTokenRequestHandler
    : IOpenIddictServerHandler<ExtractTokenRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractTokenRequestContext>()
            .UseSingletonHandler<ExtractTokenRequestHandler>()
            .SetOrder(int.MinValue + 50_000)
            .Build();

    public ValueTask HandleAsync(ExtractTokenRequestContext context)
    {
        var exchange = context.Transaction.GetRouteExchange();
        if (exchange is null)
            return default;

        context.Request = RedbRouteOpenIddictServerHelpers.CreateRequestFromExchange(exchange);
        return default;
    }
}
