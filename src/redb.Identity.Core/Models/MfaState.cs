namespace redb.Identity.Core.Models;

/// <summary>
/// Temporary state between password verification and MFA code entry.
/// Encrypted via <see cref="Services.MfaStateProtector"/> with TTL enforcement.
/// </summary>
public sealed class MfaState
{
    /// <summary>
    /// Replay-protection identifier. Unique per issued state token.
    /// Used by <c>MfaVerify</c> route's <c>IdempotentConsumer</c> to dedupe retransmits/replays
    /// (key = <c>mfa-verify:{Jti}:{code}</c>) — legitimate retry with a different code still passes through.
    /// </summary>
    public Guid Jti { get; set; }

    /// <summary>Authenticated user ID (password already verified).</summary>
    public long UserId { get; set; }

    /// <summary>Username for display on MFA page.</summary>
    public string? Username { get; set; }

    /// <summary>Available MFA methods for this user (e.g. ["totp"]).</summary>
    public string[] Methods { get; set; } = [];

    /// <summary>Original return URL from the authorization request.</summary>
    public string? ReturnUrl { get; set; }

    /// <summary>When this state was issued. Used for TTL enforcement.</summary>
    public DateTimeOffset? IssuedAt { get; set; }

    /// <summary>
    /// B3: server-side OTP identifier (see <see cref="Mfa.IServerSideOtpStore"/>). The actual
    /// plaintext code is NOT carried in the state blob — it lives in <c>_objects</c> under
    /// <c>MfaOtpProps</c> keyed by this jti, hashed. Null for TOTP.
    /// </summary>
    public Guid? OtpJti { get; set; }

    /// <summary>Masked destination for UI display (e.g. "+7***1234", "u***@example.com"). Safe to carry client-side.</summary>
    public string? OtpDestination { get; set; }

    /// <summary>Method that issued the OTP code: "sms" or "email". Null for TOTP states.</summary>
    public string? OtpMethod { get; set; }

    /// <summary>B3: absolute OTP expiry copied from <see cref="MfaOtpProps.ExpiresAt"/> for cheap pre-check.</summary>
    public DateTimeOffset? OtpExpiresAt { get; set; }

    // ── MFA-3: WebAuthn (FIDO2) challenge plumbing ──

    /// <summary>
    /// MFA-3: 32 random bytes issued at <c>webauthn/{register|assert}/begin</c>. The browser
    /// signs (or wraps in attestation) this exact value via <c>navigator.credentials.create</c>
    /// or <c>navigator.credentials.get</c>; on <c>complete</c> we verify byte-equality against
    /// the value the authenticator hashed into <c>clientDataJSON.challenge</c>. The challenge
    /// is also persisted (hashed) to <see cref="WebAuthnConsumedChallengeProps"/> at completion
    /// to enforce single-use semantics, so a captured token cannot be replayed within its
    /// 5-min TTL window. Null for non-WebAuthn flows.
    /// </summary>
    public byte[]? WebAuthnChallenge { get; set; }

    /// <summary>
    /// MFA-3: which WebAuthn ceremony this state belongs to: <c>register</c> (attestation,
    /// new credential being created) or <c>assert</c> (assertion, existing credential being
    /// used to authenticate). Mismatched flow at <c>complete</c> is rejected with
    /// <c>flow_mismatch</c>. Null for non-WebAuthn flows.
    /// </summary>
    public string? WebAuthnFlow { get; set; }

    /// <summary>
    /// MFA-3: serialized <c>AssertionOptions</c> JSON (or <c>CredentialCreateOptions</c>) issued
    /// at <c>begin</c>. <see cref="Fido2NetLib.IFido2.MakeAssertionAsync"/> /
    /// <see cref="Fido2NetLib.IFido2.MakeNewCredentialAsync"/> require the *exact same* options
    /// instance at completion time — round-tripping the JSON via the encrypted state token
    /// avoids server-side session storage while remaining tamper-proof (DataProtection signs
    /// the entire blob). Null for non-WebAuthn flows.
    /// </summary>
    public string? WebAuthnOptionsJson { get; set; }
}
