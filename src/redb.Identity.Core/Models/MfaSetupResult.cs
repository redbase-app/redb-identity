namespace redb.Identity.Core.Models;

/// <summary>
/// Result of <see cref="Services.IMfaMethod.SetupAsync"/>: contains data the user needs
/// to complete MFA enrollment (secret, QR code URI, etc.).
/// </summary>
public sealed record MfaSetupResult
{
    /// <summary>MFA method that generated this result (e.g. "totp").</summary>
    public required string MethodId { get; init; }

    /// <summary>For TOTP: base32-encoded shared secret (shown once during setup).</summary>
    public string? SecretBase32 { get; init; }

    /// <summary>For TOTP: otpauth:// URI for QR code generation.</summary>
    public string? QrUri { get; init; }

    /// <summary>
    /// Opaque, encrypted setup token (B5). The client MUST submit it back to the confirm
    /// endpoint together with the first verification code so that the candidate secret/
    /// destination can be applied atomically. Null only when <see cref="Extra"/> carries an
    /// error (initiation failed before any token was issued).
    /// </summary>
    public string? SetupToken { get; init; }

    /// <summary>Extensibility for future methods (e.g. WebAuthn challenge).</summary>
    public Dictionary<string, object>? Extra { get; init; }
}
