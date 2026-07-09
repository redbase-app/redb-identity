using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Writes the JSON Web Key Set (JWKS) response to <see cref="IExchange.Out"/>.
/// </summary>
internal sealed class ApplyJwksResponseHandler
    : IOpenIddictServerHandler<ApplyJsonWebKeySetResponseContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyJsonWebKeySetResponseContext>()
            .UseSingletonHandler<ApplyJwksResponseHandler>()
            .SetOrder(int.MaxValue - 50_000)
            .Build();

    public ValueTask HandleAsync(ApplyJsonWebKeySetResponseContext context)
    {
        var exchange = context.Transaction.GetRouteExchange();
        if (exchange is null)
            return default;

        RedbRouteOpenIddictServerHelpers.WriteResponseToExchange(exchange, context.Response);
        context.HandleRequest();
        return default;
    }
}
