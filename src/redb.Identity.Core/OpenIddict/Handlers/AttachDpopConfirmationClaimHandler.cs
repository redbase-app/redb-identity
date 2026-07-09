using System.Text.Json;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Z4 (RFC 9449 §6.1 / RFC 7800): when a DPoP proof was validated for the current
/// /token request, attaches the JWK thumbprint to the principal as the <c>cnf</c>
/// claim so the issued access token carries the proof-of-possession binding.
/// Hooks into <see cref="HandleTokenRequestContext"/> AFTER our own
/// <see cref="HandleTokenRequestHandler"/> (which sets <c>context.Principal</c>)
/// and BEFORE OpenIddict dispatches SignIn to mint the access token.
/// </summary>
internal sealed class AttachDpopConfirmationClaimHandler
    : IOpenIddictServerHandler<HandleTokenRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleTokenRequestContext>()
            .UseSingletonHandler<AttachDpopConfirmationClaimHandler>()
            // Run AFTER HandleTokenRequestHandler (which sets context.Principal at
            // OpenIddictServerHandlers.Exchange.AttachPrincipal.Descriptor.Order + 100)
            // but BEFORE the request leaves HandleTokenRequest.
            .SetOrder(OpenIddictServerHandlers.Exchange.AttachPrincipal.Descriptor.Order + 200)
            .Build();

    public ValueTask HandleAsync(HandleTokenRequestContext context)
    {
        if (!context.Transaction.Properties.TryGetValue("dpop:jkt", out var jktObj) ||
            jktObj is not string jkt || string.IsNullOrEmpty(jkt))
        {
            return default;
        }

        if (context.Principal is null)
            return default;

        var cnf = JsonSerializer.SerializeToElement(new { jkt });
        context.Principal.SetClaim("cnf", cnf);

        // Required for OpenIddict 6: claims without an explicit destination are
        // stripped from issued tokens. Send cnf to the access token only.
        var cnfClaim = context.Principal.FindFirst("cnf");
        if (cnfClaim is not null)
        {
            cnfClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken);
        }

        return default;
    }
}
