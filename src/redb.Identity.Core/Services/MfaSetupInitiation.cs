using redb.Identity.Core.Models;

namespace redb.Identity.Core.Services;

/// <summary>
/// Pure setup data returned by <see cref="IMfaMethod.InitiateSetupAsync"/>.
/// Captures everything the orchestrator needs to (a) hand a setup_token back to the
/// client and (b) reconstruct + apply the secret on confirm — without mutating
/// <see cref="MfaProps"/> first. This is the B5 fix for the "two parallel setups
/// race-overwrite the secret" bug.
/// </summary>
public sealed record MfaSetupInitiation
{
    public required string MethodId { get; init; }

    /// <summary>
    /// Method-private secret to be persisted on confirm. For TOTP this is the encrypted
    /// (DataProtection-protected) base32 shared secret; for WebAuthn it would be the
    /// credential id payload. Null for methods that don't carry a secret (SMS/Email).
    /// </summary>
    public string? EncryptedSecret { get; init; }

    /// <summary>Destination such as phone or email. Null for TOTP.</summary>
    public string? Destination { get; init; }

    /// <summary>Client-facing setup data (QR URI, masked destination, errors, etc.).</summary>
    public required MfaSetupResult ClientResult { get; init; }
}
