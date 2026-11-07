using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Writes the device authorization response to <see cref="IExchange.Out"/>.
/// </summary>
internal sealed class ApplyDeviceResponseHandler
    : IOpenIddictServerHandler<ApplyDeviceAuthorizationResponseContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyDeviceAuthorizationResponseContext>()
            .UseSingletonHandler<ApplyDeviceResponseHandler>()
            .SetOrder(int.MaxValue - 50_000)
            .Build();

    public ValueTask HandleAsync(ApplyDeviceAuthorizationResponseContext context)
    {
        var exchange = context.Transaction.GetRouteExchange();
        if (exchange is null)
            return default;

        RedbRouteOpenIddictServerHelpers.WriteResponseToExchange(exchange, context.Response);
        context.HandleRequest();
        return default;
    }
}
