namespace redb.Identity.Core.Models;

/// <summary>
/// WebAuthn (FIDO2) credential descriptor stored per user in <see cref="MfaProps.WebAuthnCredentials"/>.
/// One row per registered authenticator (Yubikey, TouchID, sync-passkey, …); multiple rows per
/// user are normal and required (passkey-providers register one credential per device-cluster).
/// <para>
/// All cryptographic verification is delegated to Fido2NetLib (<c>Fido2.MakeAssertionAsync</c>) —
/// this DTO is just the persisted shape. Equality of <see cref="CredentialId"/> is the credential's
/// primary key; the COSE-encoded <see cref="PublicKey"/> never changes, but <see cref="SignCount"/>
/// does (see field doc) and <see cref="LastUsedAt"/> is updated atomically with each successful
/// assertion under <c>LockForUpdateAsync</c> so concurrent assertions cannot lose the counter
/// advance (CTAP2 spec — counter rollback is treated as cloning evidence).
/// </para>
/// </summary>
public sealed class WebAuthnCredential
{
    /// <summary>Raw credential ID bytes. Base64url-encoded by callers when used as a dictionary key.</summary>
    public byte[] CredentialId { get; set; } = [];

    /// <summary>COSE-encoded public key bytes. Immutable for the lifetime of the credential.</summary>
    public byte[] PublicKey { get; set; } = [];

    /// <summary>
    /// Authenticator-reported signature counter. Per CTAP2 §6.1.4 it MUST be monotonically
    /// non-decreasing across assertions; a decrease (or zero from a non-zero baseline) is
    /// treated as evidence the credential was cloned and the assertion is rejected. Some
    /// modern authenticators (TouchID, Windows Hello platform authenticator, sync-passkeys)
    /// always report 0 — for those <see cref="SignCount"/> stays 0 forever and the rollback
    /// check degenerates to "0 ≥ 0" (safe).
    /// </summary>
    public long SignCount { get; set; }

    /// <summary>User-friendly device label (e.g. "YubiKey 5 NFC", "iPhone Touch ID").</summary>
    public string? DisplayName { get; set; }

    /// <summary>Authenticator AAGUID (FIDO2 attestation metadata; 16-byte GUID, base64url-encoded here).</summary>
    public string? Aaguid { get; set; }

    /// <summary>When the credential was registered.</summary>
    public DateTimeOffset RegisteredAt { get; set; }

    /// <summary>Last successful assertion timestamp.</summary>
    public DateTimeOffset? LastUsedAt { get; set; }

    /// <summary>
    /// Whether user-verification (PIN / biometric) was asserted at registration time
    /// (clientDataJSON.uv flag). MFA-3 invariant: if a credential was registered with UV,
    /// every subsequent assertion MUST also carry uv=true — downgrading from
    /// PIN/biometric-protected to mere-presence is treated as a downgrade attack and the
    /// assertion is rejected. NIST SP 800-63B AAL2-strict.
    /// </summary>
    public bool UserVerified { get; set; }

    /// <summary>
    /// FIDO2 backup-eligibility flag from the authenticator data (BE bit, byte[0] bit 3).
    /// True for sync-passkeys (iCloud Keychain, Google Password Manager, 1Password, …)
    /// which can be replicated across the user's device-cluster; false for platform-bound
    /// or single-device authenticators (Yubikey, single-Windows-device passkey).
    /// </summary>
    public bool BackupEligible { get; set; }

    /// <summary>
    /// FIDO2 current backup-state flag from the authenticator data (BS bit, byte[0] bit 4).
    /// True iff the credential is currently synced/backed-up; transitions to true once the
    /// user-cluster has at least one backup. Combined with <see cref="BackupEligible"/> this
    /// lets RPs warn "your passkey is not backed up — you may lose access if you lose this
    /// device". Updated on every assertion (Fido2NetLib re-emits the flag).
    /// </summary>
    public bool BackupState { get; set; }
}
