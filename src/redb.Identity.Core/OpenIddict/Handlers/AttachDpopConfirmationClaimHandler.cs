using System.Security.Claims;
using System.Text.Json;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Z4 (RFC 9449 §6.1 / RFC 7800): when a DPoP proof was validated for the current
/// /token request, attaches the JWK thumbprint as the <c>cnf</c> claim of the access token
/// so it carries the proof-of-possession binding.
/// <para>
/// Runs on <see cref="ProcessSignInContext"/> after OpenIddict has prepared the per-token
/// principals and before it generates the tokens. OpenIddict 7 strips <c>cnf</c> from the
/// sign-in principal when it clones the access token principal (a confirmation must never be
/// inherited from a parent token), so the claim is set on <c>AccessTokenPrincipal</c> itself,
/// and on <c>IssuedTokenPrincipal</c> when token exchange issues an access token.
/// </para>
/// </summary>
internal sealed class AttachDpopConfirmationClaimHandler
    : IOpenIddictServerHandler<ProcessSignInContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
            .UseSingletonHandler<AttachDpopConfirmationClaimHandler>()
            // After the last Prepare*Principal handler, long before GenerateAccessToken (100_000).
            .SetOrder(OpenIddictServerHandlers.PrepareUserCodePrincipal.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ProcessSignInContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!context.Transaction.Properties.TryGetValue("dpop:jkt", out var jktObj) ||
            jktObj is not string jkt || string.IsNullOrEmpty(jkt))
        {
            return default;
        }

        var cnf = JsonSerializer.SerializeToElement(new { jkt });

        if (context.AccessTokenPrincipal is ClaimsPrincipal access)
            access.SetClaim(OpenIddictConstants.Claims.Confirmation, cnf);

        if (context.IssuedTokenPrincipal is ClaimsPrincipal issued &&
            context.IssuedTokenType is OpenIddictConstants.TokenTypeIdentifiers.AccessToken)
            issued.SetClaim(OpenIddictConstants.Claims.Confirmation, cnf);

        return default;
    }
}
