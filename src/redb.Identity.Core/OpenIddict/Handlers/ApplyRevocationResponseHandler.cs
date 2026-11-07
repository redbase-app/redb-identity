using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Writes the revocation response to <see cref="IExchange.Out"/>.
/// </summary>
internal sealed class ApplyRevocationResponseHandler
    : IOpenIddictServerHandler<ApplyRevocationResponseContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyRevocationResponseContext>()
            .UseSingletonHandler<ApplyRevocationResponseHandler>()
            .SetOrder(int.MaxValue - 50_000)
            .Build();

    public ValueTask HandleAsync(ApplyRevocationResponseContext context)
    {
        var exchange = context.Transaction.GetRouteExchange();
        if (exchange is null)
            return default;

        RedbRouteOpenIddictServerHelpers.WriteResponseToExchange(exchange, context.Response);
        context.HandleRequest();
        return default;
    }
}
