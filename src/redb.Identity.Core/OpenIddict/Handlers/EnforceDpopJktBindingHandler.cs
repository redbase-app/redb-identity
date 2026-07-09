using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using redb.Identity.Core.Configuration;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Z4 P2.1 (RFC 9449 §10): if the redeemed authorization-code carries a
/// <c>oi_dpop_jkt_binding</c> claim, the token request MUST present a DPoP proof whose
/// <c>jkt</c> matches that binding. Mismatched or missing proof rejects with
/// <c>invalid_grant</c>.
/// </summary>
internal sealed class EnforceDpopJktBindingHandler
    : IOpenIddictServerHandler<HandleTokenRequestContext>
{
    private readonly DpopOptions _options;
    private readonly ILogger<EnforceDpopJktBindingHandler> _logger;

    public EnforceDpopJktBindingHandler(
        IOptions<RedbIdentityOptions> identityOptions,
        ILogger<EnforceDpopJktBindingHandler> logger)
    {
        _options = (identityOptions ?? throw new ArgumentNullException(nameof(identityOptions))).Value.Dpop;
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<HandleTokenRequestContext>()
            .UseScopedHandler<EnforceDpopJktBindingHandler>()
            // Run early — AFTER built-in AttachPrincipal but BEFORE any sign-in.
            .SetOrder(OpenIddictServerHandlers.Exchange.AttachPrincipal.Descriptor.Order + 50)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(HandleTokenRequestContext context)
    {
        if (!_options.Enabled)
            return default;

        // Only authorization_code redemption can be jkt-bound at /authorize.
        if (!context.Request.IsAuthorizationCodeGrantType())
            return default;

        var bindingJkt = context.Principal?.GetClaim(BindDpopJktAtAuthorizeHandler.ClaimType);
        if (string.IsNullOrEmpty(bindingJkt))
            return default;

        // Pull the proof's jkt the ValidateDpopProofHandler already stashed.
        if (!context.Transaction.Properties.TryGetValue("dpop:jkt", out var proofObj) ||
            proofObj is not string proofJkt || string.IsNullOrEmpty(proofJkt))
        {
            _logger.LogWarning("authorization_code carries dpop_jkt binding {Jkt} but no DPoP proof was presented at /token.", bindingJkt);
            context.Reject(
                error: Errors.InvalidGrant,
                description: "DPoP proof required: the authorization_code is bound to a DPoP key (RFC 9449 \u00a710).");
            return default;
        }

        if (!string.Equals(bindingJkt, proofJkt, StringComparison.Ordinal))
        {
            _logger.LogWarning("DPoP jkt mismatch: bound={Bound} proof={Proof}", bindingJkt, proofJkt);
            context.Reject(
                error: Errors.InvalidGrant,
                description: "DPoP proof key thumbprint does not match the dpop_jkt bound to the authorization_code.");
            return default;
        }

        _logger.LogDebug("DPoP jkt binding satisfied: {Jkt}", proofJkt);
        return default;
    }
}
