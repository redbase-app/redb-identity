using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using redb.Identity.Core.Models;

namespace redb.Identity.Core.Services;

/// <summary>
/// Encrypts/decrypts an MFA setup token (B5). The setup token carries the candidate
/// secret/destination for an in-progress MFA setup so that the secret is NEVER persisted
/// to <see cref="MfaProps"/> until the user proves possession by submitting a valid code
/// during confirm.
///
/// Uses ASP.NET DataProtection with a dedicated purpose so leaks across MFA-state /
/// MFA-secret protectors are impossible. Default TTL is 10 minutes.
/// </summary>
public sealed class MfaSetupTokenProtector
{
    private const string Purpose = "redb.identity.mfa-setup.v1";
    private static readonly TimeSpan DefaultMaxAge = TimeSpan.FromMinutes(10);

    private readonly IDataProtector _protector;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<MfaSetupTokenProtector>? _logger;

    public MfaSetupTokenProtector(IDataProtectionProvider provider)
        : this(provider, TimeProvider.System, null)
    {
    }

    public MfaSetupTokenProtector(IDataProtectionProvider provider, TimeProvider? timeProvider)
        : this(provider, timeProvider, null)
    {
    }

    public MfaSetupTokenProtector(
        IDataProtectionProvider provider,
        TimeProvider? timeProvider,
        ILogger<MfaSetupTokenProtector>? logger)
    {
        ArgumentNullException.ThrowIfNull(provider);
        _protector = provider.CreateProtector(Purpose);
        _timeProvider = timeProvider ?? TimeProvider.System;
        _logger = logger;
    }

    public string Protect(MfaSetupTokenPayload payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        if (payload.IssuedAt == default) payload.IssuedAt = _timeProvider.GetUtcNow();
        if (payload.Jti == Guid.Empty) payload.Jti = Guid.NewGuid();
        var json = JsonSerializer.SerializeToUtf8Bytes(payload);
        var encrypted = _protector.Protect(json);
        return Convert.ToBase64String(encrypted);
    }

    /// <summary>
    /// Returns the decrypted payload or null if tampered, malformed, expired, or older than
    /// <paramref name="maxAge"/> (defaults to 10 minutes).
    /// </summary>
    public MfaSetupTokenPayload? Unprotect(string token, TimeSpan? maxAge = null)
    {
        if (string.IsNullOrEmpty(token)) return null;
        try
        {
            var bytes = Convert.FromBase64String(token);
            var json = _protector.Unprotect(bytes);
            var payload = JsonSerializer.Deserialize<MfaSetupTokenPayload>(json);
            if (payload is null || payload.UserId <= 0 || string.IsNullOrEmpty(payload.MethodId))
            {
                _logger?.LogWarning(
                    "MfaSetupTokenProtector: decrypted payload was null or had invalid UserId/MethodId.");
                return null;
            }

            var age = _timeProvider.GetUtcNow() - payload.IssuedAt;
            if (age > (maxAge ?? DefaultMaxAge))
            {
                _logger?.LogDebug(
                    "MfaSetupTokenProtector: setup token expired (age={AgeSeconds}s, max={MaxSeconds}s).",
                    age.TotalSeconds, (maxAge ?? DefaultMaxAge).TotalSeconds);
                return null;
            }

            return payload;
        }
        catch (Exception ex)
        {
            // Tampering or DataProtection key rotation. Public contract preserved (null).
            _logger?.LogWarning(ex,
                "MfaSetupTokenProtector: failed to decrypt setup token (length={Length}).",
                token.Length);
            return null;
        }
    }
}
