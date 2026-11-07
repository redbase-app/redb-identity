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

        // RFC 6749 §5.2 — normalise the token-endpoint error contract. `invalid_token` is a
        // resource-server error (RFC 6750) and is NOT a valid token-endpoint error code; OpenIddict
        // emits it (HTTP 401) for an already-redeemed authorization code (ID2010), which must instead
        // be reported as `invalid_grant` with HTTP 400. Rewrite it before serialising.
        var error = context.Response.Error;
        if (error == OpenIddictConstants.Errors.InvalidToken)
        {
            context.Response.Error = OpenIddictConstants.Errors.InvalidGrant;
            error = OpenIddictConstants.Errors.InvalidGrant;
        }

        var exchange = context.Transaction.GetRouteExchange();
        if (exchange is null)
            return default;

        RedbRouteOpenIddictServerHelpers.WriteResponseToExchange(exchange, context.Response);

        // RFC 6749 §5.2 — token-endpoint error status: `invalid_client` MAY be 401 (with a
        // WWW-Authenticate challenge); every other error is 400. Set it explicitly so error codes
        // never leak a resource-server-style 401 from the token endpoint.
        if (!string.IsNullOrEmpty(error))
        {
            exchange.Out!.Headers[redb.Route.Http.HttpHeaders.ResponseCode] =
                error == OpenIddictConstants.Errors.InvalidClient ? 401 : 400;
        }

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
