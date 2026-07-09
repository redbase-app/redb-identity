using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using redb.Identity.Core.Services;

namespace redb.Identity.Resource.Dpop;

/// <summary>
/// Z4 P2.3 (RFC 9449 §7): Resource Server side validator for DPoP-bound access tokens.
/// <para>
/// Verifies that:
/// <list type="number">
///   <item>The supplied DPoP proof is structurally valid (signature, htm, htu, iat, jti).</item>
///   <item>The proof's <c>ath</c> claim equals <c>base64url(SHA-256(access_token))</c>.</item>
///   <item>The proof's JWK thumbprint matches the access-token's <c>cnf.jkt</c> claim
///         (issued by the AS via <see cref="DpopProofValidator"/> + the cnf-binding handler).</item>
/// </list>
/// The caller owns access-token signature/audience/expiry validation — typically delegated to
/// <c>OpenIddict.Validation</c> or <c>JsonWebTokenHandler</c> — and passes the already-validated
/// JWT here for the DPoP-specific checks.
/// </para>
/// </summary>
public sealed class DpopResourceTokenValidator
{
    private static readonly JsonWebTokenHandler s_handler = new();

    private readonly DpopProofValidator _proofValidator;

    public DpopResourceTokenValidator(DpopProofValidator proofValidator)
    {
        _proofValidator = proofValidator ?? throw new ArgumentNullException(nameof(proofValidator));
    }

    /// <summary>
    /// Validates a DPoP-bound access-token request.
    /// </summary>
    /// <param name="accessToken">The bearer-form access token (without the <c>DPoP </c> scheme prefix).</param>
    /// <param name="dpopProof">The raw <c>DPoP</c> request header value.</param>
    /// <param name="httpMethod">HTTP method of the protected request (e.g. <c>GET</c>).</param>
    /// <param name="httpUri">Absolute URL of the protected request, query stripped per RFC 9449 §4.2.</param>
    /// <param name="ct">Cancellation token.</param>
    public async Task<DpopResourceValidationResult> ValidateAsync(
        string accessToken,
        string dpopProof,
        string httpMethod,
        string httpUri,
        CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(accessToken))
            return DpopResourceValidationResult.Fail("invalid_token", "Missing access token.");
        if (string.IsNullOrEmpty(dpopProof))
            return DpopResourceValidationResult.Fail("invalid_token", "Missing DPoP proof header.");

        // Compute the expected `ath` claim per RFC 9449 §4.2: base64url(SHA-256(access_token)).
        var ath = ComputeAth(accessToken);

        var proofResult = await _proofValidator.ValidateAsync(
            proof: dpopProof,
            httpMethod: httpMethod,
            httpUri: httpUri,
            expectedAth: ath,
            ct: ct).ConfigureAwait(false);

        if (!proofResult.IsValid)
            return DpopResourceValidationResult.Fail(
                proofResult.Error ?? "invalid_token",
                proofResult.ErrorDescription ?? "DPoP proof validation failed.");

        // Pull cnf.jkt from the access token. We do not re-validate the JWT here — caller's job —
        // but we do need the confirmation claim. Read the payload via JsonWebTokenHandler.
        if (!s_handler.CanReadToken(accessToken))
            return DpopResourceValidationResult.Fail("invalid_token", "Access token is not a JWT.");

        var jwt = s_handler.ReadJsonWebToken(accessToken);
        if (!jwt.TryGetPayloadValue<JsonElement>("cnf", out var cnfElement) ||
            cnfElement.ValueKind != JsonValueKind.Object ||
            !cnfElement.TryGetProperty("jkt", out var jktElement) ||
            jktElement.ValueKind != JsonValueKind.String)
        {
            return DpopResourceValidationResult.Fail("invalid_token",
                "Access token is not DPoP-bound (missing cnf.jkt).");
        }

        var boundJkt = jktElement.GetString()!;
        if (!string.Equals(boundJkt, proofResult.Jkt, StringComparison.Ordinal))
        {
            return DpopResourceValidationResult.Fail("invalid_token",
                "DPoP proof key thumbprint does not match the access token cnf.jkt.");
        }

        return DpopResourceValidationResult.Success(boundJkt);
    }

    /// <summary>
    /// Builds the <c>WWW-Authenticate</c> challenge per RFC 9449 §7.1.
    /// </summary>
    /// <param name="error">OAuth-style error code (e.g. <c>invalid_token</c>, <c>insufficient_scope</c>).</param>
    /// <param name="errorDescription">Optional human-readable detail (escaped per RFC 6749 §5.2).</param>
    /// <param name="allowedAlgs">Optional space-separated list of accepted DPoP algs.</param>
    /// <param name="nonce">Optional server-issued nonce to require in the next proof.</param>
    public static string BuildChallengeHeader(
        string? error = null,
        string? errorDescription = null,
        string? allowedAlgs = "ES256 RS256",
        string? nonce = null)
    {
        var sb = new StringBuilder("DPoP");
        var hasParams = false;
        void Append(string key, string? val)
        {
            if (string.IsNullOrEmpty(val)) return;
            sb.Append(hasParams ? ", " : " ");
            sb.Append(key).Append("=\"").Append(val.Replace("\"", "")).Append('"');
            hasParams = true;
        }
        Append("error", error);
        Append("error_description", errorDescription);
        Append("algs", allowedAlgs);
        Append("nonce", nonce);
        return sb.ToString();
    }

    /// <summary>
    /// Computes the access token hash claim (<c>ath</c>) per RFC 9449 §4.2: base64url-encoded
    /// SHA-256 of the ASCII bytes of the access token.
    /// </summary>
    public static string ComputeAth(string accessToken)
    {
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(accessToken));
        return Base64UrlEncoder.Encode(hash);
    }
}

/// <summary>Result of a Resource-Server DPoP-bound token validation.</summary>
public readonly record struct DpopResourceValidationResult(
    bool IsValid,
    string? Jkt,
    string? Error,
    string? ErrorDescription)
{
    public static DpopResourceValidationResult Success(string jkt)
        => new(true, jkt, null, null);

    public static DpopResourceValidationResult Fail(string error, string description)
        => new(false, null, error, description);
}
