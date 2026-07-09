using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Extracts the userinfo request parameters from <see cref="IExchange.In"/>.
/// Additionally extracts Bearer token from the Authorization header.
/// </summary>
internal sealed class ExtractUserinfoRequestHandler
    : IOpenIddictServerHandler<ExtractUserInfoRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractUserInfoRequestContext>()
            .UseSingletonHandler<ExtractUserinfoRequestHandler>()
            .SetOrder(int.MinValue + 50_000)
            .Build();

    public ValueTask HandleAsync(ExtractUserInfoRequestContext context)
    {
        var exchange = context.Transaction.GetRouteExchange();
        if (exchange is null)
            return default;

        context.Request = RedbRouteOpenIddictServerHelpers.CreateRequestFromExchange(exchange);

        // Userinfo typically receives the access token via Bearer scheme
        if (string.IsNullOrEmpty(context.Request.AccessToken)
            && exchange.In.Headers.TryGetValue("Authorization", out var authValue)
            && authValue is string auth
            && auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            context.Request.AccessToken = auth["Bearer ".Length..].Trim();
        }

        return default;
    }
}
