using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using redb.Identity.Core.Configuration;

namespace redb.Identity.Core.Services;

/// <summary>
/// Provides the server-wide pepper applied during MFA recovery-code hashing
/// (B4 — defence-in-depth on top of per-user salt + PBKDF2).
///
/// Singleton lifetime: pepper bytes are decoded once at construction so every
/// <see cref="MfaService"/> instance shares the same value.
/// </summary>
public sealed class RecoveryCodePepperProvider
{
    /// <summary>Raw pepper bytes (configured or ephemeral). Never empty.</summary>
    public byte[] Pepper { get; }

    /// <summary>True if the pepper was generated at startup (development fallback).</summary>
    public bool IsEphemeral { get; }

    public RecoveryCodePepperProvider(
        IOptions<RedbIdentityOptions> options,
        ILogger<RecoveryCodePepperProvider> logger)
    {
        var configured = options.Value.RecoveryCodePepper;

        if (!string.IsNullOrEmpty(configured))
        {
            byte[] bytes;
            try
            {
                bytes = Convert.FromBase64String(configured);
            }
            catch (FormatException ex)
            {
                throw new InvalidOperationException(
                    "RedbIdentityOptions.RecoveryCodePepper must be a valid base64 string.", ex);
            }
            if (bytes.Length < 16)
            {
                throw new InvalidOperationException(
                    "RedbIdentityOptions.RecoveryCodePepper must decode to at least 16 bytes; got "
                    + bytes.Length + ".");
            }
            Pepper = bytes;
            IsEphemeral = false;
            return;
        }

        if (!options.Value.AllowEphemeralKeys)
        {
            throw new InvalidOperationException(
                "RedbIdentityOptions.RecoveryCodePepper is not configured. " +
                "Set AllowEphemeralKeys=true in development, or provide a stable base64-encoded " +
                "pepper (16+ bytes) loaded from a secret store in production.");
        }

        Pepper = RandomNumberGenerator.GetBytes(32);
        IsEphemeral = true;
        logger.LogWarning(
            "MFA recovery-code pepper is ephemeral: codes generated in this process cannot be " +
            "verified after restart. Set RedbIdentityOptions.RecoveryCodePepper for production.");
    }

    private RecoveryCodePepperProvider(byte[] pepper, bool isEphemeral)
    {
        Pepper = pepper;
        IsEphemeral = isEphemeral;
    }

    /// <summary>
    /// Test-only factory: builds a provider with a fixed (or random 32-byte) pepper without
    /// going through configuration validation. Use exclusively in unit / integration tests.
    /// </summary>
    public static RecoveryCodePepperProvider ForTesting(byte[]? pepper = null) =>
        new(pepper ?? RandomNumberGenerator.GetBytes(32), isEphemeral: pepper is null);
}
