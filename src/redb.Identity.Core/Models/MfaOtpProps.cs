using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// B3: server-side OTP material for SMS / Email MFA methods.
/// <para>
/// The plaintext OTP lives <b>only</b> in memory between generation and delivery; what we
/// persist is the SHA-256 hash of the plaintext (so a database leak does not disclose
/// live codes). <see cref="Jti"/> is a per-issuance random identifier; the client-side
/// state (see <see cref="MfaState"/>) carries it instead of the plaintext code, so the
/// code never appears in URLs / HTTP logs / referer headers.
/// </para>
/// <para>
/// Consumption is single-use: <see cref="Consumed"/> flips to <c>true</c> atomically under
/// <c>LockForUpdate</c> during verify, and subsequent attempts against the same
/// <see cref="Jti"/> are rejected regardless of code correctness. Expired
/// (<see cref="ExpiresAt"/> &lt; now) or consumed rows are soft-deleted by the
/// <c>timer://identity-mfa-otp-cleanup</c> route.
/// </para>
/// </summary>
[RedbScheme("identity.mfa_otp")]
public class MfaOtpProps
{
    /// <summary>Random per-issuance identifier. Matches <see cref="MfaState.OtpJti"/>.</summary>
    public string Jti { get; set; } = "";

    /// <summary>Owner user id (joined to <c>_users</c>).</summary>
    public long UserId { get; set; }

    /// <summary>Delivery method that issued this OTP: <c>sms</c> or <c>email</c>.</summary>
    public string Method { get; set; } = "";

    /// <summary>SHA-256 of the plaintext OTP, lowercase hex. Never store plaintext.</summary>
    public string CodeHash { get; set; } = "";

    /// <summary>Masked destination for UI display (e.g. <c>+7***1234</c>, <c>u***@example.com</c>).</summary>
    public string DestinationMasked { get; set; } = "";

    /// <summary>Issue timestamp (UTC).</summary>
    public DateTimeOffset IssuedAt { get; set; }

    /// <summary>Absolute expiry — verify requests after this instant fail regardless of code.</summary>
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>
    /// True once a successful verify has consumed the code. Mutated under <c>LockForUpdate</c>
    /// to enforce single-use semantics even under concurrent verify attempts.
    /// </summary>
    public bool Consumed { get; set; }

    /// <summary>
    /// Count of verify attempts (success+fail). Used by the cleanup route to highlight abuse
    /// and by diagnostics; not directly consulted for rate-limiting (that lives on
    /// <c>MfaProps.OtpAttemptsSinceLastSent</c>).
    /// </summary>
    public int Attempts { get; set; }
}
