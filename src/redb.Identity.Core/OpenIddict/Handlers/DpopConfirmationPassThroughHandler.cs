using System.Security.Claims;
using System.Text.Json.Nodes;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Validation;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// OpenIddict 7 checks the <c>cnf</c> claim of every token it validates and knows only the mTLS form
/// (<c>x5t#S256</c>, RFC 8705): any other confirmation, such as the DPoP key thumbprint <c>jkt</c>
/// (RFC 9449) that <see cref="AttachDpopConfirmationClaimHandler"/> puts in access tokens, makes it throw
/// (ID2196) and the request ends in server_error. A DPoP-bound token therefore skips OpenIddict's
/// proof-of-possession check; the DPoP proof itself is Identity's business (<see cref="ValidateDpopProofHandler"/>
/// at the token endpoint, <c>redb.Identity.Resource.Dpop</c> at resource servers). A certificate-bound token
/// (<c>x5t#S256</c>, alone or alongside <c>jkt</c>) keeps OpenIddict's check.
/// </summary>
internal static class DpopConfirmationPassThrough
{
    internal static bool IsDpopOnly(ClaimsPrincipal? principal)
    {
        var confirmation = principal?.GetClaim(Claims.Confirmation);
        if (string.IsNullOrEmpty(confirmation))
            return false;

        try
        {
            return JsonNode.Parse(confirmation) is JsonObject cnf
                && cnf.ContainsKey("jkt")
                && !cnf.ContainsKey("x5t#S256");
        }
        catch (System.Text.Json.JsonException)
        {
            return false; // malformed: leave it to OpenIddict, which rejects it
        }
    }
}

/// <summary>Server stack (userinfo, introspection, revocation): see <see cref="DpopConfirmationPassThrough"/>.</summary>
internal sealed class DpopConfirmationServerPassThroughHandler
    : IOpenIddictServerHandler<OpenIddictServerEvents.ValidateTokenContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<OpenIddictServerEvents.ValidateTokenContext>()
            .UseSingletonHandler<DpopConfirmationServerPassThroughHandler>()
            .SetOrder(OpenIddictServerHandlers.Protection.ValidateProofOfPossession.Descriptor.Order - 1)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(OpenIddictServerEvents.ValidateTokenContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (DpopConfirmationPassThrough.IsDpopOnly(context.Principal))
            context.DisableProofOfPossessionValidation = true;
        return default;
    }
}

/// <summary>Validation stack (bearer tokens on the management API): see <see cref="DpopConfirmationPassThrough"/>.</summary>
internal sealed class DpopConfirmationValidationPassThroughHandler
    : IOpenIddictValidationHandler<OpenIddictValidationEvents.ValidateTokenContext>
{
    public static OpenIddictValidationHandlerDescriptor Descriptor { get; } =
        OpenIddictValidationHandlerDescriptor.CreateBuilder<OpenIddictValidationEvents.ValidateTokenContext>()
            .UseSingletonHandler<DpopConfirmationValidationPassThroughHandler>()
            .SetOrder(OpenIddictValidationHandlers.Protection.ValidateProofOfPossession.Descriptor.Order - 1)
            .SetType(OpenIddictValidationHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(OpenIddictValidationEvents.ValidateTokenContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (DpopConfirmationPassThrough.IsDpopOnly(context.Principal))
            context.DisableProofOfPossessionValidation = true;
        return default;
    }
}
