using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Extracts the end-user verification request parameters from <see cref="IExchange.In"/>.
/// Part of the Device Code Flow (RFC 8628 §3.3).
/// </summary>
internal sealed class ExtractVerificationRequestHandler
    : IOpenIddictServerHandler<ExtractEndUserVerificationRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractEndUserVerificationRequestContext>()
            .UseSingletonHandler<ExtractVerificationRequestHandler>()
            .SetOrder(int.MinValue + 50_000)
            .Build();

    public ValueTask HandleAsync(ExtractEndUserVerificationRequestContext context)
    {
        var exchange = context.Transaction.GetRouteExchange();
        if (exchange is null)
            return default;

        context.Request = RedbRouteOpenIddictServerHelpers.CreateRequestFromExchange(exchange);
        return default;
    }
}
