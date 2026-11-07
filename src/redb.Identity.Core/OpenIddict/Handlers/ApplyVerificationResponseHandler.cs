using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Writes the end-user verification response to <see cref="IExchange.Out"/>.
/// Part of the Device Code Flow (RFC 8628 §3.3).
/// </summary>
internal sealed class ApplyVerificationResponseHandler
    : IOpenIddictServerHandler<ApplyEndUserVerificationResponseContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyEndUserVerificationResponseContext>()
            .UseSingletonHandler<ApplyVerificationResponseHandler>()
            .SetOrder(int.MaxValue - 50_000)
            .Build();

    public ValueTask HandleAsync(ApplyEndUserVerificationResponseContext context)
    {
        var exchange = context.Transaction.GetRouteExchange();
        if (exchange is null)
            return default;

        RedbRouteOpenIddictServerHelpers.WriteResponseToExchange(exchange, context.Response);
        context.HandleRequest();
        return default;
    }
}
