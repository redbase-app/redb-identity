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

        // The access token comes in the Authorization header under the Bearer scheme, or under the DPoP
        // scheme for a DPoP-bound token (RFC 9449 §7.1). Whether the scheme fits the token is checked by
        // DpopConfirmationServerPassThroughHandler once the token is validated.
        if (string.IsNullOrEmpty(context.Request.AccessToken)
            && exchange.In.Headers.TryGetValue("Authorization", out var authValue)
            && authValue is string auth)
        {
            foreach (var scheme in (ReadOnlySpan<string>)["Bearer ", "DPoP "])
            {
                if (auth.StartsWith(scheme, StringComparison.OrdinalIgnoreCase))
                {
                    context.Request.AccessToken = auth[scheme.Length..].Trim();
                    break;
                }
            }
        }

        return default;
    }
}
