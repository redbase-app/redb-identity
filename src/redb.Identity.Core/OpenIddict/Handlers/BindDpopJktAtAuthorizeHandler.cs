using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using redb.Identity.Core.Configuration;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Z4 P2.1 (RFC 9449 §10): if the authorization request carries a <c>dpop_jkt</c> parameter,
/// validate its format and bind it as a private claim on the issued authorization-code principal.
/// At the token endpoint, <see cref="EnforceDpopJktBindingHandler"/> requires the inbound DPoP
/// proof's <c>jkt</c> to match this claim.
/// <para>
/// The claim is added with an empty <c>Destinations</c> set so it persists in the auth-code
/// principal serialization but never leaks into issued access / id tokens.
/// </para>
/// </summary>
internal sealed class BindDpopJktAtAuthorizeHandler
    : IOpenIddictServerHandler<HandleAuthorizationRequestContext>
{
    /// <summary>Internal claim type used to carry the bound jkt across requests.</summary>
    public const string ClaimType = "oi_dpop_jkt_binding";

    private readonly DpopOptions _options;
    private readonly ILogger<BindDpopJktAtAuthorizeHandler> _logger;

    public BindDpopJktAtAuthorizeHandler(
        IOptions<RedbIdentityOptions> identityOptions,
        ILogger<BindDpopJktAtAuthorizeHandler> logger)
    {
        _options = (identityOptions ?? throw new ArgumentNullException(nameof(identityOptions))).Value.Dpop;
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<HandleAuthorizationRequestContext>()
            .UseScopedHandler<BindDpopJktAtAuthorizeHandler>()
            // Must run AFTER HandleAuthorizationRequestHandler so a principal exists,
            // but BEFORE the AttachAuthorizationCode default handler so the claim is included.
            .SetOrder(OpenIddictServerHandlers.Authentication.AttachPrincipal.Descriptor.Order + 200)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(HandleAuthorizationRequestContext context)
    {
        if (!_options.Enabled)
            return default;

        if (context.Principal is null)
            return default;

        var jkt = (string?)context.Request["dpop_jkt"];
        if (string.IsNullOrEmpty(jkt))
            return default;

        if (!IsWellFormedJkt(jkt))
        {
            _logger.LogWarning("Authorize request rejected: malformed dpop_jkt parameter (length={Len})", jkt.Length);
            context.Reject(
                error: Errors.InvalidRequest,
                description: "dpop_jkt parameter must be a base64url-encoded SHA-256 thumbprint (43 chars).");
            return default;
        }

        if (context.Principal.Identity is not ClaimsIdentity identity)
            return default;

        // Add binding claim with empty destinations: persisted in auth-code, absent from tokens.
        var claim = new Claim(ClaimType, jkt);
        identity.AddClaim(claim);
        claim.SetDestinations(Array.Empty<string>());

        _logger.LogDebug("Bound dpop_jkt {Jkt} to authorization-code principal (RFC 9449 \u00a710).", jkt);
        return default;
    }

    /// <summary>
    /// Per RFC 9449 §10 the parameter is a JWK thumbprint per RFC 7638: SHA-256 base64url-encoded
    /// without padding ⇒ exactly 43 base64url characters [A-Za-z0-9_-].
    /// </summary>
    private static bool IsWellFormedJkt(string value)
    {
        if (value.Length != 43) return false;
        foreach (var ch in value)
        {
            var ok = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                     (ch >= '0' && ch <= '9') || ch == '-' || ch == '_';
            if (!ok) return false;
        }
        return true;
    }
}
