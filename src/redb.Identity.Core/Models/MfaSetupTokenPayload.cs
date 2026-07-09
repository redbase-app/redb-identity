namespace redb.Identity.Core.Models;

/// <summary>
/// Encrypted payload of an MFA setup token (B5). Bound to a single user + setup attempt
/// via <see cref="Jti"/>; protected with DataProtection purpose
/// <c>"redb.identity.mfa-setup.v1"</c> and capped by a 10-minute TTL.
/// Not exposed publicly — round-trips between client and server as an opaque string.
/// </summary>
public sealed class MfaSetupTokenPayload
{
    public long UserId { get; set; }
    public string MethodId { get; set; } = string.Empty;
    public string? EncryptedSecret { get; set; }
    public string? Destination { get; set; }
    public DateTimeOffset IssuedAt { get; set; }
    public Guid Jti { get; set; }

    /// <summary>
    /// MFA-3: 32 random challenge bytes for an in-progress WebAuthn registration ceremony.
    /// Echoed by the browser inside <c>clientDataJSON.challenge</c>; verified byte-equal at
    /// confirm time by Fido2NetLib. Once the registration completes, the SHA-256 hash of
    /// these bytes is written to <see cref="WebAuthnConsumedChallengeProps"/> so a captured
    /// setup-token cannot be replayed within the 10-min TTL. Null for non-WebAuthn flows.
    /// </summary>
    public byte[]? WebAuthnChallenge { get; set; }

    /// <summary>
    /// MFA-3: serialized <c>CredentialCreateOptions</c> JSON for the in-progress registration.
    /// Fido2NetLib's <c>MakeNewCredentialAsync</c> needs the *exact same* options instance back
    /// at confirm time — we round-trip it via the encrypted setup token so no server-side
    /// session state is needed. Null for non-WebAuthn flows.
    /// </summary>
    public string? WebAuthnOptionsJson { get; set; }
}
