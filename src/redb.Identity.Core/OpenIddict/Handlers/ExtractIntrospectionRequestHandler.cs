using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Extracts the introspection request parameters from <see cref="IExchange.In"/>.
/// </summary>
internal sealed class ExtractIntrospectionRequestHandler
    : IOpenIddictServerHandler<ExtractIntrospectionRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractIntrospectionRequestContext>()
            .UseSingletonHandler<ExtractIntrospectionRequestHandler>()
            .SetOrder(int.MinValue + 50_000)
            .Build();

    public ValueTask HandleAsync(ExtractIntrospectionRequestContext context)
    {
        var exchange = context.Transaction.GetRouteExchange();
        if (exchange is null)
            return default;

        context.Request = RedbRouteOpenIddictServerHelpers.CreateRequestFromExchange(exchange);
        return default;
    }
}
