using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;

namespace redb.Identity.Core.Services;

/// <summary>
/// Encrypts/decrypts TOTP secrets at rest using ASP.NET DataProtection.
/// Unlike <see cref="MfaStateProtector"/>, no TTL — secrets live until user disables MFA.
/// </summary>
public sealed class MfaSecretProtector
{
    private const string Purpose = "redb.identity.mfa-secret";

    private readonly IDataProtector _protector;
    private readonly ILogger<MfaSecretProtector>? _logger;

    public MfaSecretProtector(IDataProtectionProvider provider, ILogger<MfaSecretProtector>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(provider);
        _protector = provider.CreateProtector(Purpose);
        _logger = logger;
    }

    /// <summary>Encrypts a plaintext secret (e.g. base32-encoded TOTP key).</summary>
    public string Protect(string plainSecret)
    {
        ArgumentNullException.ThrowIfNull(plainSecret);
        var bytes = System.Text.Encoding.UTF8.GetBytes(plainSecret);
        var encrypted = _protector.Protect(bytes);
        return Convert.ToBase64String(encrypted);
    }

    /// <summary>Decrypts a protected secret. Returns null if decryption fails (tampered/rotated keys).</summary>
    public string? Unprotect(string protectedSecret)
    {
        if (string.IsNullOrEmpty(protectedSecret))
            return null;

        try
        {
            var encrypted = Convert.FromBase64String(protectedSecret);
            var bytes = _protector.Unprotect(encrypted);
            return System.Text.Encoding.UTF8.GetString(bytes);
        }
        catch (Exception ex)
        {
            // Log every decrypt failure: each one is either a security signal (tampered ciphertext)
            // or an operational alert (DataProtection key rotation/loss). Returning null keeps the
            // public contract intact for callers (treat as "secret unavailable").
            _logger?.LogWarning(ex,
                "MfaSecretProtector: failed to decrypt protected MFA secret (length={Length}).",
                protectedSecret.Length);
            return null;
        }
    }
}
