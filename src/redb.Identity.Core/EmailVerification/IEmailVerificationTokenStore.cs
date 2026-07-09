using System;
using System.Threading;
using System.Threading.Tasks;

namespace redb.Identity.Core.EmailVerification;

/// <summary>
/// N-4 (Session C, sub-step N4-6): server-side e-mail-verification token store. Mirror of
/// <see cref="PasswordReset.IPasswordResetTokenStore"/> with one extra binding — the
/// token is tied to the specific e-mail value snapshot captured at issue time, so a
/// stale link cannot vouch for an address the user has since changed.
/// </summary>
public interface IEmailVerificationTokenStore
{
    /// <summary>
    /// Issues a new verification token. Generates a 32-byte CSPRNG secret
    /// (base64url-encoded), persists its peppered SHA-256 hash + the bound
    /// <paramref name="email"/> snapshot, and returns the <c>jti</c> + plaintext token so
    /// the caller can embed both into the verify URL.
    /// </summary>
    /// <param name="userId">User the verification is bound to.</param>
    /// <param name="email">
    /// Lower-cased snapshot of the user's e-mail at issue time. Confirm rejects the token
    /// when the user's current e-mail no longer matches this value (double-change race).
    /// </param>
    /// <param name="callerVerifyUrl">
    /// Caller-supplied landing URL captured at issue time. Recorded for audit; the
    /// whitelist check is enforced by the issuing processor against
    /// <c>ApplicationProps.EmailVerifyUris</c>.
    /// </param>
    /// <param name="ttl">Time-to-live for this token. Typically 24 hours.</param>
    Task<EmailVerificationIssueResult> IssueAsync(
        long userId,
        string email,
        string callerVerifyUrl,
        TimeSpan ttl,
        CancellationToken ct = default);

    /// <summary>
    /// Verifies and atomically consumes a verification token keyed by <paramref name="jti"/>.
    /// On success the row is marked <c>Consumed</c> and the bound <c>UserId</c> + e-mail
    /// snapshot are returned so the caller can apply the e-mail-match guard before
    /// flipping <c>UserProps.EmailVerified</c>.
    /// </summary>
    Task<EmailVerificationVerifyResult> VerifyAndConsumeAsync(
        Guid jti,
        string token,
        CancellationToken ct = default);
}

/// <summary>Result of <see cref="IEmailVerificationTokenStore.IssueAsync"/>.</summary>
public readonly record struct EmailVerificationIssueResult(
    Guid Jti,
    string PlaintextToken,
    DateTimeOffset ExpiresAt);

/// <summary>Result of <see cref="IEmailVerificationTokenStore.VerifyAndConsumeAsync"/>.</summary>
/// <param name="Success">Whether the token verified AND the row was successfully consumed.</param>
/// <param name="UserId">Owner user id when <see cref="Success"/> is <c>true</c>; otherwise <c>0</c>.</param>
/// <param name="Email">Lower-cased e-mail snapshot bound at issue time; empty when <see cref="Success"/> is <c>false</c>.</param>
/// <param name="Reason">Diagnostic reason; values: <c>ok</c>, <c>not_found</c>, <c>expired</c>, <c>already_consumed</c>, <c>bad_token</c>.</param>
public readonly record struct EmailVerificationVerifyResult(
    bool Success,
    long UserId,
    string Email,
    string Reason);
