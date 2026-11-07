using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;

namespace redb.Identity.Core.Services;

/// <summary>
/// H8 (DoD §4 gap (e)): encrypts/decrypts federation provider client secrets at rest
/// using ASP.NET DataProtection. Mirrors <see cref="MfaSecretProtector"/> in shape;
/// distinct purpose string keeps key isolation between unrelated subsystems.
/// </summary>
public sealed class FederationProviderSecretProtector
{
    private const string Purpose = "redb.identity.federation-provider-secret";

    private readonly IDataProtector _protector;
    private readonly ILogger<FederationProviderSecretProtector>? _logger;

    public FederationProviderSecretProtector(
        IDataProtectionProvider provider,
        ILogger<FederationProviderSecretProtector>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(provider);
        _protector = provider.CreateProtector(Purpose);
        _logger = logger;
    }

    /// <summary>Encrypts a plaintext secret. Returns null when input is null/empty.</summary>
    public string? Protect(string? plainSecret)
    {
        if (string.IsNullOrEmpty(plainSecret)) return null;
        var bytes = System.Text.Encoding.UTF8.GetBytes(plainSecret);
        var encrypted = _protector.Protect(bytes);
        return Convert.ToBase64String(encrypted);
    }

    /// <summary>Decrypts a protected secret. Returns null on failure (rotated/lost keys).</summary>
    public string? Unprotect(string? protectedSecret)
    {
        if (string.IsNullOrEmpty(protectedSecret)) return null;
        try
        {
            var encrypted = Convert.FromBase64String(protectedSecret);
            var bytes = _protector.Unprotect(encrypted);
            return System.Text.Encoding.UTF8.GetString(bytes);
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex,
                "FederationProviderSecretProtector: failed to decrypt federation provider secret (length={Length}).",
                protectedSecret.Length);
            return null;
        }
    }
}
