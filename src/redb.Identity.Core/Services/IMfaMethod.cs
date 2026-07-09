using redb.Identity.Core.Models;

namespace redb.Identity.Core.Services;

/// <summary>
/// SPI for MFA verification methods (TOTP, SMS, WebAuthn, etc.).
/// Implementations are stateless — they receive <see cref="MfaProps"/> directly
/// and never load/save data. Orchestration is done by <see cref="MfaService"/>.
/// </summary>
public interface IMfaMethod
{
    /// <summary>Unique method identifier (e.g. "totp", "sms", "email").</summary>
    string MethodId { get; }

    /// <summary>
    /// Pure setup: generates the candidate secret/destination and the client-facing payload
    /// (QR URI, masked destination, …) WITHOUT mutating <see cref="MfaProps"/>.
    /// The orchestrator wraps the returned <see cref="MfaSetupInitiation"/> in an encrypted
    /// setup token (B5) which the client must present back during confirm. This eliminates the
    /// "two parallel setups overwrite the secret" race.
    /// </summary>
    /// <param name="username">Username for QR label (TOTP). May be ignored by other methods.</param>
    /// <param name="destination">Phone/email for SMS/Email methods. Ignored by TOTP/WebAuthn.</param>
    Task<MfaSetupInitiation> InitiateSetupAsync(string username, string? destination = null, CancellationToken ct = default);

    /// <summary>
    /// Verifies the user-supplied code against the candidate setup data and, on success,
    /// writes the secret/destination into <paramref name="props"/>. Single atomic step —
    /// caller must persist <paramref name="props"/> only after this method returns true.
    /// </summary>
    /// <param name="state">
    /// Decrypted MFA challenge state for SMS/Email (carries <see cref="MfaState.OtpJti"/>
    /// referencing <c>MfaOtpProps</c>). Null for TOTP.
    /// </param>
    Task<bool> ConfirmAndApplyAsync(MfaProps props, MfaSetupInitiation initiation, string code, MfaState? state = null, CancellationToken ct = default);

    /// <summary>Verify code during login.</summary>
    /// <param name="state">
    /// Decrypted MFA state for SMS/Email (carries <see cref="MfaState.OtpJti"/> referencing
    /// server-side OTP material). Null/ignored for TOTP.
    /// </param>
    Task<bool> VerifyAsync(MfaProps props, string code, MfaState? state = null, CancellationToken ct = default);
}
