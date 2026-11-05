using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Validation;
using redb.Identity.Core.Services;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Proof of possession for DPoP-bound access tokens (RFC 9449 §7) at the server's own protected endpoints:
/// /connect/userinfo and the management API.
/// <para>
/// OpenIddict 7 checks the <c>cnf</c> claim of every token it validates and knows only the mTLS form
/// (<c>x5t#S256</c>, RFC 8705): any other confirmation, such as the DPoP key thumbprint <c>jkt</c> that
/// <see cref="AttachDpopConfirmationClaimHandler"/> puts in access tokens, makes it throw (ID2196). A DPoP-only
/// token therefore skips OpenIddict's check, and the DPoP proof is verified here instead, in the same handler,
/// so the check is never turned off without the replacement having run.
/// </para>
/// <para>
/// A token whose <c>cnf</c> carries <c>jkt</c> is accepted only under the <c>DPoP</c> authorization scheme with a
/// proof signed by the bound key, matching the request method and URL, carrying the token hash (<c>ath</c>) and
/// not seen before. A token without <c>jkt</c> under the <c>DPoP</c> scheme is rejected. A certificate-bound token
/// keeps OpenIddict's check; with <c>jkt</c> alongside, the DPoP proof is required as well.
/// </para>
/// </summary>
internal static class DpopConfirmationPassThrough
{
    /// <summary>The authorization scheme for DPoP-bound access tokens (RFC 9449 §7.1).</summary>
    internal const string DpopScheme = "DPoP";

    /// <summary>Validation-stack transaction property: the authorization scheme the token came with.</summary>
    internal const string SchemeProperty = "identity:dpop-resource-scheme";

    /// <summary>Validation-stack transaction property: the raw <c>DPoP</c> request header.</summary>
    internal const string ProofProperty = "identity:dpop-resource-proof";

    /// <summary>Validation-stack transaction property: the HTTP method of the protected request.</summary>
    internal const string MethodProperty = "identity:dpop-resource-method";

    /// <summary>Validation-stack transaction property: the absolute URL of the protected request.</summary>
    internal const string UrlProperty = "identity:dpop-resource-url";

    /// <summary>
    /// Exchange (server stack) or transaction (validation stack) property: the <c>WWW-Authenticate</c> value for a
    /// rejection made here.
    /// </summary>
    internal const string ChallengeProperty = "identity:dpop-resource-challenge";

    /// <summary>RFC 9449 §7.1 challenge: <c>DPoP error="invalid_token", error_description="..."</c>.</summary>
    internal static string BuildChallenge(string description)
    {
        var safe = description.Replace("\\", "\\\\").Replace("\"", "\\\"");
        return $"{DpopScheme} error=\"{Errors.InvalidToken}\", error_description=\"{safe}\"";
    }

    internal static bool IsDpopOnly(ClaimsPrincipal? principal)
    {
        var cnf = ReadConfirmation(principal);
        return cnf is not null && cnf.ContainsKey("jkt") && !cnf.ContainsKey("x5t#S256");
    }

    /// <summary>The DPoP key thumbprint the token is bound to, or <c>null</c> when it has none.</summary>
    internal static string? BoundJkt(ClaimsPrincipal? principal)
    {
        var cnf = ReadConfirmation(principal);
        if (cnf is null || !cnf.TryGetPropertyValue("jkt", out var node) || node is not JsonValue value)
            return null;
        return value.TryGetValue<string>(out var jkt) && !string.IsNullOrEmpty(jkt) ? jkt : null;
    }

    /// <summary>
    /// Checks how a token is presented at a protected endpoint. Returns <c>null</c> when the request may proceed,
    /// otherwise the description of an <c>invalid_token</c> rejection.
    /// </summary>
    internal static async ValueTask<string?> CheckPresentationAsync(
        DpopProofValidator validator,
        ClaimsPrincipal? principal,
        string? token,
        string? scheme,
        string? proof,
        string? method,
        string? url,
        CancellationToken ct)
    {
        var dpopScheme = string.Equals(scheme, DpopScheme, StringComparison.OrdinalIgnoreCase);
        var boundJkt = BoundJkt(principal);

        if (boundJkt is null)
            return dpopScheme ? "The access token is not bound to a DPoP key." : null;

        if (!dpopScheme)
            return "A DPoP-bound access token must be presented with the DPoP authorization scheme.";

        if (string.IsNullOrEmpty(proof))
            return "A DPoP proof is required for a DPoP-bound access token.";

        if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(method) || string.IsNullOrEmpty(url))
            return "The DPoP proof cannot be checked on this transport.";

        var result = await validator.ValidateAsync(
            proof: proof,
            httpMethod: method,
            httpUri: url,
            expectedAth: ComputeAth(token),
            ct: ct).ConfigureAwait(false);

        if (!result.IsValid)
            return result.ErrorDescription ?? "The DPoP proof is invalid.";

        if (!string.Equals(result.Jkt, boundJkt, StringComparison.Ordinal))
            return "The DPoP proof key does not match the key the access token is bound to.";

        return null;
    }

    /// <summary>RFC 9449 §4.2 <c>ath</c>: base64url SHA-256 of the ASCII access token.</summary>
    internal static string ComputeAth(string accessToken)
        => Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)));

    /// <summary>Splits an <c>Authorization</c> header into its scheme; <c>null</c> when there is none.</summary>
    internal static string? SchemeOf(string? authorizationHeader)
    {
        if (string.IsNullOrWhiteSpace(authorizationHeader))
            return null;
        var trimmed = authorizationHeader.TrimStart();
        var end = trimmed.IndexOfAny([' ', '\t']);
        return end < 0 ? trimmed : trimmed[..end];
    }

    private static JsonObject? ReadConfirmation(ClaimsPrincipal? principal)
    {
        var confirmation = principal?.GetClaim(Claims.Confirmation);
        if (string.IsNullOrEmpty(confirmation))
            return null;

        try
        {
            return JsonNode.Parse(confirmation) as JsonObject;
        }
        catch (System.Text.Json.JsonException)
        {
            return null; // malformed: leave it to OpenIddict, which rejects it
        }
    }
}

/// <summary>
/// Server stack: proof of possession at /connect/userinfo (see <see cref="DpopConfirmationPassThrough"/>).
/// Introspection and revocation are called by the client or resource server with its own credentials and carry
/// no proof; for them only OpenIddict's check is skipped.
/// </summary>
internal sealed class DpopConfirmationServerPassThroughHandler
    : IOpenIddictServerHandler<OpenIddictServerEvents.ValidateTokenContext>
{
    private readonly DpopProofValidator _validator;

    public DpopConfirmationServerPassThroughHandler(DpopProofValidator validator)
        => _validator = validator ?? throw new ArgumentNullException(nameof(validator));

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<OpenIddictServerEvents.ValidateTokenContext>()
            .UseSingletonHandler<DpopConfirmationServerPassThroughHandler>()
            .SetOrder(OpenIddictServerHandlers.Protection.ValidateProofOfPossession.Descriptor.Order - 1)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(OpenIddictServerEvents.ValidateTokenContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.EndpointType is OpenIddictServerEndpointType.UserInfo)
        {
            var exchange = context.Transaction.GetRouteExchange();
            var error = await DpopConfirmationPassThrough.CheckPresentationAsync(
                _validator,
                context.Principal,
                context.Token,
                DpopConfirmationPassThrough.SchemeOf(exchange?.In.GetHeader<string>("Authorization")),
                exchange?.In.GetHeader<string>("DPoP"),
                exchange?.In.GetHeader<string>("redbHttp.Method"),
                exchange?.In.GetHeader<string>("redbHttp.Url"),
                context.CancellationToken).ConfigureAwait(false);

            if (error is not null)
            {
                if (exchange is not null)
                    exchange.Properties[DpopConfirmationPassThrough.ChallengeProperty] = DpopConfirmationPassThrough.BuildChallenge(error);
                context.Reject(error: Errors.InvalidToken, description: error);
                return;
            }
        }

        if (DpopConfirmationPassThrough.IsDpopOnly(context.Principal))
            context.DisableProofOfPossessionValidation = true;
    }
}

/// <summary>
/// Validation stack: proof of possession at the management API (see <see cref="DpopConfirmationPassThrough"/>).
/// The request details come from the transaction properties set by
/// <see cref="Routes.Processors.ManagementBearerAuthProcessor"/>.
/// </summary>
internal sealed class DpopConfirmationValidationPassThroughHandler
    : IOpenIddictValidationHandler<OpenIddictValidationEvents.ValidateTokenContext>
{
    private readonly DpopProofValidator _validator;

    public DpopConfirmationValidationPassThroughHandler(DpopProofValidator validator)
        => _validator = validator ?? throw new ArgumentNullException(nameof(validator));

    public static OpenIddictValidationHandlerDescriptor Descriptor { get; } =
        OpenIddictValidationHandlerDescriptor.CreateBuilder<OpenIddictValidationEvents.ValidateTokenContext>()
            .UseSingletonHandler<DpopConfirmationValidationPassThroughHandler>()
            .SetOrder(OpenIddictValidationHandlers.Protection.ValidateProofOfPossession.Descriptor.Order - 1)
            .SetType(OpenIddictValidationHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(OpenIddictValidationEvents.ValidateTokenContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var properties = context.Transaction.Properties;
        var error = await DpopConfirmationPassThrough.CheckPresentationAsync(
            _validator,
            context.Principal,
            context.Token,
            Read(properties, DpopConfirmationPassThrough.SchemeProperty),
            Read(properties, DpopConfirmationPassThrough.ProofProperty),
            Read(properties, DpopConfirmationPassThrough.MethodProperty),
            Read(properties, DpopConfirmationPassThrough.UrlProperty),
            context.CancellationToken).ConfigureAwait(false);

        if (error is not null)
        {
            properties[DpopConfirmationPassThrough.ChallengeProperty] = DpopConfirmationPassThrough.BuildChallenge(error);
            context.Reject(error: Errors.InvalidToken, description: error);
            return;
        }

        if (DpopConfirmationPassThrough.IsDpopOnly(context.Principal))
            context.DisableProofOfPossessionValidation = true;

        static string? Read(IDictionary<string, object?> properties, string key)
            => properties.TryGetValue(key, out var value) ? value as string : null;
    }
}
