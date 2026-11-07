using System;
using System.Threading;
using System.Threading.Tasks;

namespace redb.Identity.Core.PasswordReset;

/// <summary>
/// N-4 (Session C): server-side password-reset token store — issues and atomically consumes
/// single-use reset tokens so that the plaintext token lives only in transient memory
/// (generator → e-mail channel) and never appears in the database, access logs, or referer
/// headers.
/// <para>
/// Mirrors <see cref="Mfa.IServerSideOtpStore"/>: each issuance writes a single row
/// containing <c>sha256(pepper || token)</c>, an absolute <see cref="MaxAge"/> TTL, and a
/// single-use flag. Verify loads the row under <c>LockForUpdate</c>, checks the hash in
/// constant time, flips the flag, commits — so a second verify with the same token hits an
/// already-consumed row and fails regardless of correctness.
/// </para>
/// </summary>
public interface IPasswordResetTokenStore
{
    /// <summary>
    /// Issues a new reset token. Generates a 32-byte CSPRNG secret (base64url-encoded),
    /// persists its peppered SHA-256 hash, and returns the <c>jti</c> + plaintext token so
    /// the caller can embed both into the e-mail link.
    /// </summary>
    /// <param name="userId">User the reset is bound to.</param>
    /// <param name="callerResetUrl">
    /// The caller-supplied reset URL captured at issue time. Recorded for audit; the
    /// whitelist / open-redirect check is enforced by the HTTP facade against the configured
    /// allow-list before this method is invoked.
    /// </param>
    /// <param name="ttl">Time-to-live for this token. Typically 30 minutes.</param>
    Task<PasswordResetIssueResult> IssueAsync(
        long userId,
        string callerResetUrl,
        TimeSpan ttl,
        CancellationToken ct = default);

    /// <summary>
    /// Verifies and atomically consumes a reset token keyed by <paramref name="jti"/>. On
    /// success the row is marked <c>Consumed</c> and the bound <c>UserId</c> is returned;
    /// on failure <c>Attempts</c> increments so downstream telemetry can flag guessing
    /// attempts. Already-consumed, expired, or unknown <paramref name="jti"/> values return
    /// <see cref="PasswordResetVerifyResult.Success"/> = <c>false</c> with the appropriate
    /// <see cref="PasswordResetVerifyResult.Reason"/>.
    /// </summary>
    /// <param name="jti">Per-issuance identifier carried on the reset URL.</param>
    /// <param name="token">Plaintext token carried on the reset URL.</param>
    Task<PasswordResetVerifyResult> VerifyAndConsumeAsync(
        Guid jti,
        string token,
        CancellationToken ct = default);
}

/// <summary>Result of <see cref="IPasswordResetTokenStore.IssueAsync"/>.</summary>
/// <param name="Jti">Random per-issuance identifier. Embed into the reset URL.</param>
/// <param name="PlaintextToken">Plaintext token for e-mail delivery. Must NOT be persisted by the caller.</param>
/// <param name="ExpiresAt">Absolute expiry; surface as <c>{ttlMinutes}</c> in the e-mail template.</param>
public readonly record struct PasswordResetIssueResult(
    Guid Jti,
    string PlaintextToken,
    DateTimeOffset ExpiresAt);

/// <summary>Result of <see cref="IPasswordResetTokenStore.VerifyAndConsumeAsync"/>.</summary>
/// <param name="Success">Whether the token verified AND the row was successfully consumed.</param>
/// <param name="UserId">Owner user id when <see cref="Success"/> is <c>true</c>; otherwise <c>0</c>.</param>
/// <param name="Reason">Diagnostic reason; values: <c>ok</c>, <c>not_found</c>, <c>expired</c>,
/// <c>already_consumed</c>, <c>bad_token</c>.</param>
public readonly record struct PasswordResetVerifyResult(
    bool Success,
    long UserId,
    string Reason);
