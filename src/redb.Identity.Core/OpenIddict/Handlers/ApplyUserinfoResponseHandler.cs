using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Writes the userinfo response to <see cref="IExchange.Out"/>.
/// </summary>
internal sealed class ApplyUserinfoResponseHandler
    : IOpenIddictServerHandler<ApplyUserInfoResponseContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyUserInfoResponseContext>()
            .UseSingletonHandler<ApplyUserinfoResponseHandler>()
            .SetOrder(int.MaxValue - 50_000)
            .Build();

    public ValueTask HandleAsync(ApplyUserInfoResponseContext context)
    {
        var exchange = context.Transaction.GetRouteExchange();
        if (exchange is null)
            return default;

        RedbRouteOpenIddictServerHelpers.WriteResponseToExchange(exchange, context.Response);
        context.HandleRequest();
        return default;
    }
}
