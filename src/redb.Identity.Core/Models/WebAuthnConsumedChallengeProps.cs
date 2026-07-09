using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// MFA-3: server-side single-use marker for consumed WebAuthn challenges.
/// <para>
/// The 32-byte challenge issued at <c>register/begin</c> or <c>assert/begin</c> is encrypted
/// into the client-facing setup-token / mfa_state for convenience (no DB hit on issue), but
/// completion of the ceremony writes a row here and rejects retries with the same challenge.
/// This closes the replay window between issue and natural TTL expiry — without it, a captured
/// `setup_token` containing a still-fresh challenge could be replayed within the 5-min TTL.
/// </para>
/// <para>
/// We persist <see cref="ChallengeHash"/> (SHA-256 hex of challenge bytes) — not the raw
/// challenge — so a database leak does not expose live challenges to an attacker who would
/// otherwise need a stolen DataProtector key to forge them. The hash is sufficient for
/// equality-detection on consume.
/// </para>
/// <para>
/// Atomicity: <see cref="WebAuthnMfaMethod"/> writes this row inside the same transaction as
/// the credential persistence (registration) or sign-counter advance (assertion); a unique
/// index on <see cref="ChallengeHash"/> makes second-consume race-safe — duplicate insert
/// fails fast with <c>replay_detected</c>. Cleanup runs via
/// <c>timer://identity-mfa-webauthn-challenge-cleanup</c> once <see cref="ExpiresAt"/> is past.
/// </para>
/// </summary>
[RedbScheme("identity.webauthn_consumed_challenge")]
public class WebAuthnConsumedChallengeProps
{
    /// <summary>SHA-256 hex (lowercase) of the raw challenge bytes. Indexed for replay detection.</summary>
    public string ChallengeHash { get; set; } = "";

    /// <summary>Owner user id; cross-checked at consume time to reject cross-user replay.</summary>
    public long UserId { get; set; }

    /// <summary>Operation that consumed the challenge: <c>register</c> or <c>assert</c>.</summary>
    public string Operation { get; set; } = "";

    /// <summary>When the consumed marker was written (UTC). Equal to ceremony-completion time.</summary>
    public DateTimeOffset ConsumedAt { get; set; }

    /// <summary>
    /// Absolute expiry of the original challenge — after this point the marker can be cleaned
    /// up because no fresh assertion can carry the same challenge (TTL on the encrypted token
    /// matches this). Cleanup processor checks <c>ExpiresAt &lt; now</c>.
    /// </summary>
    public DateTimeOffset ExpiresAt { get; set; }
}
