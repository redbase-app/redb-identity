using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using redb.Identity.Core.Configuration;

namespace redb.Identity.Core.Services;

/// <summary>
/// Z4 (RFC 9449): validates a DPoP proof JWT and reserves its <c>jti</c>
/// against the configured <see cref="IDpopReplayStore"/>.
/// </summary>
public sealed class DpopProofValidator
{
    private static readonly JsonWebTokenHandler _handler = new();

    private readonly IDpopReplayStore _replayStore;
    private readonly DpopOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<DpopProofValidator> _logger;

    public DpopProofValidator(
        IDpopReplayStore replayStore,
        IOptions<RedbIdentityOptions> identityOptions,
        ILogger<DpopProofValidator> logger,
        TimeProvider? timeProvider = null)
    {
        _replayStore = replayStore ?? throw new ArgumentNullException(nameof(replayStore));
        _options = (identityOptions ?? throw new ArgumentNullException(nameof(identityOptions))).Value.Dpop;
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Validates a DPoP proof JWT bound to the given HTTP method + URL.
    /// </summary>
    /// <param name="proof">The raw <c>DPoP</c> header value (a JWS compact-serialization JWT).</param>
    /// <param name="httpMethod">HTTP method of the protected request (e.g. <c>POST</c>).</param>
    /// <param name="httpUri">Absolute URL of the protected request, with query stripped per RFC 9449 §4.2.</param>
    /// <param name="expectedAth">Optional expected <c>ath</c> claim (SHA-256 of access-token, base64url) — required at resource servers, not at /token.</param>
    /// <param name="ct">Cancellation token.</param>
    public async Task<DpopValidationResult> ValidateAsync(
        string proof,
        string httpMethod,
        string httpUri,
        string? expectedAth = null,
        CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(proof))
            return DpopValidationResult.Fail("invalid_dpop_proof", "DPoP header missing.");

        if (!_handler.CanReadToken(proof))
            return DpopValidationResult.Fail("invalid_dpop_proof", "DPoP proof is not a well-formed JWT.");

        JsonWebToken parsed;
        try { parsed = _handler.ReadJsonWebToken(proof); }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "DPoP proof parse failed");
            return DpopValidationResult.Fail("invalid_dpop_proof", "DPoP proof is malformed.");
        }

        // Header checks (RFC 9449 §4.2)
        if (!parsed.TryGetHeaderValue<string>("typ", out var typ) ||
            !string.Equals(typ, "dpop+jwt", StringComparison.Ordinal))
        {
            return DpopValidationResult.Fail("invalid_dpop_proof", "DPoP proof typ must be 'dpop+jwt'.");
        }

        if (!parsed.TryGetHeaderValue<string>("alg", out var alg) ||
            string.IsNullOrEmpty(alg) ||
            string.Equals(alg, "none", StringComparison.OrdinalIgnoreCase) ||
            !_options.AllowedSigningAlgorithms.Contains(alg, StringComparer.Ordinal))
        {
            return DpopValidationResult.Fail("invalid_dpop_proof",
                $"DPoP proof alg '{alg}' is not in the allowed list.");
        }

        // The embedded JWK in the header is the proof's verification key.
        if (!parsed.TryGetHeaderValue<JsonElement>("jwk", out var jwkElement))
        {
            return DpopValidationResult.Fail("invalid_dpop_proof", "DPoP proof jwk header is missing.");
        }

        JsonWebKey jwk;
        try
        {
            jwk = new JsonWebKey(jwkElement.GetRawText());
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "DPoP jwk parse failed");
            return DpopValidationResult.Fail("invalid_dpop_proof", "DPoP proof jwk is malformed.");
        }

        // Reject any private-key components — the proof MUST carry only the public key.
        if (!string.IsNullOrEmpty(jwk.D))
            return DpopValidationResult.Fail("invalid_dpop_proof", "DPoP proof jwk MUST NOT contain a private key.");

        // Verify signature
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = jwk,
            ValidAlgorithms = _options.AllowedSigningAlgorithms,
        };

        var validation = await _handler.ValidateTokenAsync(proof, validationParameters).ConfigureAwait(false);
        if (!validation.IsValid)
        {
            _logger.LogDebug(validation.Exception, "DPoP signature validation failed");
            return DpopValidationResult.Fail("invalid_dpop_proof", "DPoP proof signature is invalid.");
        }

        // Claim checks
        if (!parsed.TryGetPayloadValue<string>("htm", out var htm) ||
            !string.Equals(htm, httpMethod, StringComparison.OrdinalIgnoreCase))
        {
            return DpopValidationResult.Fail("invalid_dpop_proof",
                $"DPoP proof htm '{htm}' does not match request method '{httpMethod}'.");
        }

        if (!parsed.TryGetPayloadValue<string>("htu", out var htu))
            return DpopValidationResult.Fail("invalid_dpop_proof", "DPoP proof htu claim is missing.");

        if (!HtuMatches(htu, httpUri))
        {
            return DpopValidationResult.Fail("invalid_dpop_proof",
                $"DPoP proof htu '{htu}' does not match request URI '{httpUri}'.");
        }

        if (!parsed.TryGetPayloadValue<long>("iat", out var iat))
            return DpopValidationResult.Fail("invalid_dpop_proof", "DPoP proof iat claim is missing.");

        var nowSeconds = _timeProvider.GetUtcNow().ToUnixTimeSeconds();
        var skew = Math.Abs(nowSeconds - iat);
        if (skew > _options.IatToleranceSeconds)
        {
            return DpopValidationResult.Fail("invalid_dpop_proof",
                $"DPoP proof iat is outside the {_options.IatToleranceSeconds}s tolerance window.");
        }

        if (!parsed.TryGetPayloadValue<string>("jti", out var jti) || string.IsNullOrEmpty(jti))
            return DpopValidationResult.Fail("invalid_dpop_proof", "DPoP proof jti claim is missing.");

        if (expectedAth is not null)
        {
            if (!parsed.TryGetPayloadValue<string>("ath", out var ath) ||
                !CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(ath ?? ""),
                    Encoding.ASCII.GetBytes(expectedAth)))
            {
                return DpopValidationResult.Fail("invalid_dpop_proof",
                    "DPoP proof ath claim does not match the access token hash.");
            }
        }

        // Extract optional nonce claim — nonce policy is enforced by the calling handler
        // against an IDpopNonceProvider (RFC 9449 §8). The validator only surfaces the value.
        parsed.TryGetPayloadValue<string>("nonce", out var nonce);

        // Compute jkt (RFC 7638 SHA-256 thumbprint)
        var jkt = ComputeJwkThumbprint(jwk);

        // Replay check — reserve (jkt, jti) for the iat tolerance window (×2 for safety).
        var ttl = TimeSpan.FromSeconds(_options.IatToleranceSeconds * 2);
        var reserved = await _replayStore.TryReserveAsync(jkt, jti, ttl, ct).ConfigureAwait(false);
        if (!reserved)
        {
            return DpopValidationResult.Fail("invalid_dpop_proof", "DPoP proof has already been used (replay).");
        }

        return DpopValidationResult.Success(jkt, jti, nonce);
    }

    /// <summary>
    /// Compares request URL to the proof's <c>htu</c> claim per RFC 9449 §4.3:
    /// query and fragment are stripped from both sides; case-insensitive scheme/host;
    /// path comparison is case-sensitive.
    /// </summary>
    private static bool HtuMatches(string htu, string requestUri)
    {
        return string.Equals(Normalise(htu), Normalise(requestUri), StringComparison.Ordinal);

        static string Normalise(string value)
        {
            if (!Uri.TryCreate(value, UriKind.Absolute, out var u))
                return value;
            // Drop query + fragment; lowercase scheme + host.
            var builder = new UriBuilder(u) { Query = "", Fragment = "" };
            builder.Scheme = builder.Scheme.ToLowerInvariant();
            builder.Host = builder.Host.ToLowerInvariant();
            // UriBuilder injects default port — strip when implied.
            if ((builder.Scheme == "http" && builder.Port == 80) ||
                (builder.Scheme == "https" && builder.Port == 443))
            {
                builder.Port = -1;
            }
            // Trim trailing slash for symmetric comparison.
            var s = builder.Uri.ToString();
            return s.EndsWith('/') ? s.TrimEnd('/') : s;
        }
    }

    /// <summary>
    /// Computes the RFC 7638 JWK SHA-256 thumbprint, base64url-encoded.
    /// Microsoft.IdentityModel exposes <see cref="JsonWebKey.ComputeJwkThumbprint"/>
    /// returning raw bytes; we base64url-encode without padding per RFC 7515.
    /// </summary>
    public static string ComputeJwkThumbprint(JsonWebKey jwk)
    {
        var bytes = jwk.ComputeJwkThumbprint();
        return Base64UrlEncoder.Encode(bytes);
    }
}

/// <summary>Result of a DPoP proof validation.</summary>
public readonly record struct DpopValidationResult(
    bool IsValid,
    string? Jkt,
    string? Jti,
    string? Nonce,
    string? Error,
    string? ErrorDescription)
{
    public static DpopValidationResult Success(string jkt, string jti, string? nonce = null)
        => new(true, jkt, jti, nonce, null, null);

    public static DpopValidationResult Fail(string error, string description)
        => new(false, null, null, null, error, description);
}
