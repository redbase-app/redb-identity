using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// PROPS entity storing MFA configuration and secrets for a user.
/// Key = userId (_users._id). Separate from UserProps: different concern (security vs profile),
/// loaded only during login + MFA setup (not on every request).
/// </summary>
[RedbScheme("identity.mfa")]
public class MfaProps
{
    /// <summary>Whether MFA is globally enabled for this user.</summary>
    public bool Enabled { get; set; }

    /// <summary>Default MFA method ID ("totp"). Used when multiple methods available.</summary>
    public string? DefaultMethod { get; set; }

    /// <summary>
    /// TOTP shared secret, encrypted at rest via <see cref="Services.MfaSecretProtector"/>.
    /// Null if TOTP not configured.
    /// </summary>
    public string? TotpSecret { get; set; }

    /// <summary>Whether TOTP has been confirmed (user entered first valid code after setup).</summary>
    public bool TotpConfirmed { get; set; }

    /// <summary>
    /// SHA256-hashed recovery codes. Each code is one-time use.
    /// Null until MFA is first confirmed.
    /// </summary>
    public List<string>? RecoveryCodes { get; set; }

    /// <summary>
    /// Archive of recovery-code batches that were retired (e.g. when MFA was disabled or
    /// regenerated). Holding the previous hashes lets an admin audit
    /// «which codes were active before the wipe» without making them usable for login —
    /// they are NEVER consulted by <c>VerifyRecoveryCodeAsync</c>. Append-only;
    /// pruning policy belongs to a future admin-tools sprint. Null on rows that have never
    /// been archived (B9 / BUG-8).
    /// </summary>
    public List<MfaArchivedRecoveryCodeBatch>? ArchivedRecoveryCodes { get; set; }

    /// <summary>Consecutive failed MFA verification attempts (for lockout).</summary>
    public int FailedAttempts { get; set; }

    /// <summary>Account locked until this time after too many failed attempts. Null if not locked.</summary>
    public DateTimeOffset? LockedUntil { get; set; }

    /// <summary>Timestamp of last successful MFA verification.</summary>
    public DateTimeOffset? LastVerifiedAt { get; set; }

    /// <summary>
    /// Last accepted TOTP time-step (Unix-seconds / 30) — RFC 6238 §5.2 replay protection.
    /// A login attempt with a step ≤ this value is rejected even if the 6-digit code is
    /// otherwise valid within the verification window. Null until the first successful
    /// TOTP verify (legacy rows).
    /// </summary>
    public long? LastTotpStep { get; set; }

    // ── SMS OTP ──

    /// <summary>Phone number for SMS OTP (E.164 format, e.g. "+79991234567"). Null if SMS not configured.</summary>
    public string? SmsPhone { get; set; }

    /// <summary>Whether SMS OTP has been confirmed (user entered first valid code).</summary>
    public bool SmsConfirmed { get; set; }

    // ── Email OTP ──

    /// <summary>Email address for OTP delivery (may differ from profile email). Null if not configured.</summary>
    public string? OtpEmail { get; set; }

    /// <summary>Whether Email OTP has been confirmed (user entered first valid code).</summary>
    public bool EmailConfirmed { get; set; }

    // ── WebAuthn (FIDO2) — skeleton only, full implementation deferred to MFA-3 ──

    /// <summary>
    /// WebAuthn credentials keyed by base64url credential ID.
    /// Skeleton field: shape only — no register/verify implementation yet.
    /// </summary>
    public Dictionary<string, WebAuthnCredential>? WebAuthnCredentials { get; set; }

    // ── Rate limiting (SMS/Email send throttle) ──

    /// <summary>Timestamp of last OTP send (for cooldown enforcement).</summary>
    public DateTimeOffset? LastOtpSentAt { get; set; }

    /// <summary>
    /// Sliding-window record of recent OTP send timestamps (Unix seconds).
    /// On each send the list is pruned (entries older than 1 hour are dropped) and the
    /// current timestamp is appended; capped at 50 entries to bound storage. Used to enforce
    /// <see cref="Configuration.RedbIdentityOptions.OtpMaxPerHour"/> over a true rolling window
    /// (B6) instead of a calendar-hour bucket (which would let an attacker burst OTPs at the
    /// hour boundary).
    /// </summary>
    public List<long>? RecentOtpTimestamps { get; set; }
}
