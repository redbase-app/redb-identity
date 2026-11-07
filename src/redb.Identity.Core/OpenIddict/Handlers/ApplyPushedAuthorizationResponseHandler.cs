using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Writes the Pushed Authorization Response (RFC 9126 §2.2 — request_uri/expires_in,
/// or error) to <see cref="IExchange.Out"/> with HTTP 201 Created on success.
/// </summary>
internal sealed class ApplyPushedAuthorizationResponseHandler
    : IOpenIddictServerHandler<ApplyPushedAuthorizationResponseContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyPushedAuthorizationResponseContext>()
            .UseSingletonHandler<ApplyPushedAuthorizationResponseHandler>()
            .SetOrder(int.MaxValue - 50_000)
            .Build();

    public ValueTask HandleAsync(ApplyPushedAuthorizationResponseContext context)
    {
        var exchange = context.Transaction.GetRouteExchange();
        if (exchange is null)
            return default;

        RedbRouteOpenIddictServerHelpers.WriteResponseToExchange(exchange, context.Response);

        // RFC 9126 §2.2: 201 Created on success. On error, fall through to the
        // OAuth-error → HTTP-status mapper applied by the HTTP facade.
        if (string.IsNullOrEmpty(context.Response.Error) && exchange.HasOut && exchange.Out is not null)
        {
            exchange.Out.Headers["redbHttp.ResponseCode"] = 201;
        }

        context.HandleRequest();
        return default;
    }
}
