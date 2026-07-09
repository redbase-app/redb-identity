using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using redb.Identity.Core.Configuration;

namespace redb.Identity.Core.Services;

/// <summary>
/// Z4 P2 (RFC 9449 §8): provider of server-issued DPoP nonces. Implementations may be
/// stateless (HMAC-signed timestamps) or stateful (Redis/redb). The default registered
/// implementation is <see cref="HmacDpopNonceProvider"/> — stateless, lock-free, and
/// safe to use in single-process deployments. For a clustered Identity tier set
/// <see cref="DpopOptions.NonceSigningSecret"/> to a shared value so any server can
/// validate nonces issued by any other.
/// </summary>
public interface IDpopNonceProvider
{
    /// <summary>Issues a fresh nonce string suitable for the <c>DPoP-Nonce</c> header.</summary>
    string IssueNonce();

    /// <summary>
    /// Returns <c>true</c> when the supplied nonce is well-formed, signature-valid
    /// and within <see cref="DpopOptions.NonceLifetime"/> of issuance.
    /// </summary>
    bool ValidateNonce(string nonce);
}

/// <summary>
/// Stateless HMAC-SHA256 nonce provider. Each nonce encodes a Unix-second timestamp and
/// 16 random bytes plus an HMAC; validation re-computes the HMAC and checks the timestamp
/// against <see cref="DpopOptions.NonceLifetime"/>.
/// <para>
/// Format: <c>base64url(timestamp_be8 || rand16 || hmac_sha256(secret, timestamp_be8 || rand16))</c>.
/// </para>
/// </summary>
public sealed class HmacDpopNonceProvider : IDpopNonceProvider
{
    private readonly DpopOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly byte[] _secret;

    public HmacDpopNonceProvider(IOptions<RedbIdentityOptions> identityOptions, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(identityOptions);
        _options = identityOptions.Value.Dpop;
        _timeProvider = timeProvider ?? TimeProvider.System;

        if (!string.IsNullOrEmpty(_options.NonceSigningSecret))
            _secret = Encoding.UTF8.GetBytes(_options.NonceSigningSecret);
        else
            _secret = RandomNumberGenerator.GetBytes(32);
    }

    public string IssueNonce()
    {
        Span<byte> payload = stackalloc byte[8 + 16];
        var ts = _timeProvider.GetUtcNow().ToUnixTimeSeconds();
        BitConverter.TryWriteBytes(payload[..8], !BitConverter.IsLittleEndian ? ts : System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(ts));
        RandomNumberGenerator.Fill(payload[8..]);

        Span<byte> mac = stackalloc byte[32];
        HMACSHA256.HashData(_secret, payload, mac);

        Span<byte> token = stackalloc byte[payload.Length + mac.Length];
        payload.CopyTo(token);
        mac.CopyTo(token[payload.Length..]);
        return Base64UrlEncoder.Encode(token.ToArray());
    }

    public bool ValidateNonce(string nonce)
    {
        if (string.IsNullOrEmpty(nonce)) return false;

        byte[] decoded;
        try { decoded = Base64UrlEncoder.DecodeBytes(nonce); }
        catch { return false; }

        // 8 ts + 16 rand + 32 mac = 56
        if (decoded.Length != 56) return false;

        var payload = decoded.AsSpan(0, 24);
        var providedMac = decoded.AsSpan(24, 32);

        Span<byte> expectedMac = stackalloc byte[32];
        HMACSHA256.HashData(_secret, payload, expectedMac);

        if (!CryptographicOperations.FixedTimeEquals(providedMac, expectedMac))
            return false;

        var tsBe = BitConverter.ToInt64(payload[..8]);
        var ts = !BitConverter.IsLittleEndian
            ? tsBe
            : System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(tsBe);
        var now = _timeProvider.GetUtcNow().ToUnixTimeSeconds();
        var ageSeconds = now - ts;
        if (ageSeconds < -5)
            return false; // future-dated beyond clock skew
        return ageSeconds <= (long)_options.NonceLifetime.TotalSeconds;
    }
}
