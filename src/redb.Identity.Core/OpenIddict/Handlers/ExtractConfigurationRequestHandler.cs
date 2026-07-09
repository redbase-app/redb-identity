using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Extracts the discovery (configuration) request from <see cref="IExchange.In"/>.
/// Discovery is a simple GET with no parameters, so we just set an empty request.
/// </summary>
internal sealed class ExtractConfigurationRequestHandler
    : IOpenIddictServerHandler<ExtractConfigurationRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractConfigurationRequestContext>()
            .UseSingletonHandler<ExtractConfigurationRequestHandler>()
            .SetOrder(int.MinValue + 50_000)
            .Build();

    public ValueTask HandleAsync(ExtractConfigurationRequestContext context)
    {
        var exchange = context.Transaction.GetRouteExchange();
        if (exchange is null)
            return default;

        // Discovery endpoint is a simple GET — set an empty OpenIddict request
        context.Request = new OpenIddictRequest();
        return default;
    }
}
