using System;
using System.Threading;
using System.Threading.Tasks;

namespace redb.Identity.Core.Mfa;

/// <summary>
/// B3: server-side OTP store — issues and consumes SMS/Email one-time codes so that the
/// plaintext OTP lives only in transient memory (generator → delivery channel) and never
/// appears in the encrypted <c>mfa_state</c> blob, URL query strings, access logs, or
/// Referer headers.
/// <para>
/// The resulting model is classic OTP-issuance: each challenge writes a single row
/// containing the <em>hash</em> of the code, an absolute <see cref="MaxAge"/> TTL, and a
/// single-use flag. Verify loads the row under <c>LockForUpdate</c>, checks the hash in
/// constant time, flips the flag, commits — so a second verify with the same code hits a
/// already-consumed row and fails regardless of correctness.
/// </para>
/// </summary>
public interface IServerSideOtpStore
{
    /// <summary>
    /// Issues a new OTP. Generates a CSPRNG 6-digit code, persists its SHA-256 hash, and
    /// returns the <c>jti</c> + plaintext code so the caller can deliver the plaintext via
    /// the SMS/Email channel and embed <paramref name="ttl"/> → <c>ExpiresAt</c> into
    /// the encrypted <c>mfa_state</c> via <see cref="Models.MfaState.OtpJti"/>.
    /// </summary>
    /// <param name="userId">User the challenge is bound to.</param>
    /// <param name="method"><c>sms</c> or <c>email</c>.</param>
    /// <param name="destinationMasked">Masked destination (already sanitized for UI display).</param>
    /// <param name="ttl">Time-to-live for this challenge. Typically 5 minutes.</param>
    Task<OtpIssueResult> IssueAsync(
        long userId,
        string method,
        string destinationMasked,
        TimeSpan ttl,
        CancellationToken ct = default);

    /// <summary>
    /// Verifies and atomically consumes an OTP keyed by <paramref name="jti"/>. On success
    /// the row is marked <c>Consumed</c>; on failure <c>Attempts</c> increments so downstream
    /// telemetry can flag guessing attempts. Already-consumed or expired rows return
    /// <see cref="OtpVerifyResult.Success"/> = <c>false</c> with the appropriate
    /// <see cref="OtpVerifyResult.Reason"/>.
    /// </summary>
    /// <param name="userId">Expected owner. Used as a defence-in-depth cross-check; a mismatch
    /// forces <c>Success=false</c> with <c>Reason="user_mismatch"</c>.</param>
    Task<OtpVerifyResult> VerifyAndConsumeAsync(
        Guid jti,
        long userId,
        string code,
        CancellationToken ct = default);
}

/// <summary>Result of <see cref="IServerSideOtpStore.IssueAsync"/>.</summary>
/// <param name="Jti">Random per-issuance identifier.</param>
/// <param name="PlaintextCode">Plaintext code for channel delivery. Must NOT be persisted by the caller.</param>
/// <param name="DestinationMasked">Echoed masked destination for UI display.</param>
/// <param name="ExpiresAt">Absolute expiry passed to <see cref="Models.MfaState"/> consumers.</param>
public readonly record struct OtpIssueResult(
    Guid Jti,
    string PlaintextCode,
    string DestinationMasked,
    DateTimeOffset ExpiresAt);

/// <summary>Result of <see cref="IServerSideOtpStore.VerifyAndConsumeAsync"/>.</summary>
/// <param name="Success">Whether the code verified AND the row was successfully consumed.</param>
/// <param name="Reason">Diagnostic reason; values: <c>ok</c>, <c>not_found</c>, <c>expired</c>,
/// <c>already_consumed</c>, <c>user_mismatch</c>, <c>bad_code</c>.</param>
/// <param name="Method">Method string (<c>sms</c>/<c>email</c>) recorded on the row, if loaded.</param>
public readonly record struct OtpVerifyResult(bool Success, string Reason, string? Method = null);
