using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Writes the token response to <see cref="IExchange.Out"/>.
/// </summary>
internal sealed class ApplyTokenResponseHandler
    : IOpenIddictServerHandler<ApplyTokenResponseContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyTokenResponseContext>()
            .UseSingletonHandler<ApplyTokenResponseHandler>()
            .SetOrder(int.MaxValue - 50_000)
            .Build();

    public ValueTask HandleAsync(ApplyTokenResponseContext context)
    {
        // Z4 (RFC 9449 §6): if a DPoP proof was bound earlier in the pipeline,
        // override the response token_type from "Bearer" to "DPoP" right before
        // the response is serialised onto the exchange.
        if (context.Transaction.Properties.TryGetValue("dpop:jkt", out var jktObj) &&
            jktObj is string jkt && !string.IsNullOrEmpty(jkt))
        {
            context.Response[OpenIddictConstants.Parameters.TokenType] = "DPoP";
        }

        var exchange = context.Transaction.GetRouteExchange();
        if (exchange is null)
            return default;

        RedbRouteOpenIddictServerHelpers.WriteResponseToExchange(exchange, context.Response);

        // Z4 P2 (RFC 9449 §8): if the validation pipeline staged a fresh nonce,
        // emit it as the DPoP-Nonce response header for clients to adopt. Done AFTER
        // WriteResponseToExchange so Out is initialised.
        if (exchange.HasOut &&
            exchange.Properties.TryGetValue("dpop:nonce-to-issue", out var nonceObj) &&
            nonceObj is string nonce && !string.IsNullOrEmpty(nonce))
        {
            exchange.Out!.Headers["DPoP-Nonce"] = nonce;
        }

        context.HandleRequest();
        return default;
    }
}
