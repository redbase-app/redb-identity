using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Extracts the JWKS request from <see cref="IExchange.In"/>.
/// JWKS is a simple GET with no parameters, so we just set an empty request.
/// </summary>
internal sealed class ExtractJwksRequestHandler
    : IOpenIddictServerHandler<ExtractJsonWebKeySetRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractJsonWebKeySetRequestContext>()
            .UseSingletonHandler<ExtractJwksRequestHandler>()
            .SetOrder(int.MinValue + 50_000)
            .Build();

    public ValueTask HandleAsync(ExtractJsonWebKeySetRequestContext context)
    {
        var exchange = context.Transaction.GetRouteExchange();
        if (exchange is null)
            return default;

        // JWKS endpoint is a simple GET — set an empty OpenIddict request
        context.Request = new OpenIddictRequest();
        return default;
    }
}
