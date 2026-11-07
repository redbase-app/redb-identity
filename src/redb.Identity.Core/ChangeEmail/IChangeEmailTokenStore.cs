using System;
using System.Threading;
using System.Threading.Tasks;

namespace redb.Identity.Core.ChangeEmail;

/// <summary>
/// N-4 (Session E, sub-step N4-7): server-side store for single-use
/// change-of-e-mail tokens. Direct mirror of
/// <see cref="EmailVerification.IEmailVerificationTokenStore"/> with two extra bindings —
/// the address the user wants to switch <em>to</em> (<c>newEmail</c>) and a snapshot of
/// the address at issue time (<c>currentEmail</c>) so the confirm step can detect a
/// race where the e-mail was modified through another path between request and confirm.
/// </summary>
public interface IChangeEmailTokenStore
{
    /// <summary>
    /// Issues a new change-of-e-mail token. Generates a 32-byte CSPRNG secret
    /// (base64url-encoded), persists its peppered SHA-256 hash + the bound
    /// <paramref name="newEmail"/> and <paramref name="currentEmail"/> snapshots, and
    /// returns the <c>jti</c> + plaintext token so the caller can embed both into the
    /// confirm URL.
    /// </summary>
    /// <param name="userId">User the change is bound to.</param>
    /// <param name="newEmail">Lower-cased target address (committed on confirm).</param>
    /// <param name="currentEmail">Lower-cased snapshot of the user's e-mail at issue time.</param>
    /// <param name="callerConfirmUrl">Caller-supplied landing URL captured at issue time.</param>
    /// <param name="ttl">Time-to-live for this token. Typically 1 hour.</param>
    /// <param name="invalidatePrevious">When <c>true</c>, mark all prior unconsumed tokens
    /// for this user as <c>Consumed</c> so a stolen earlier link cannot race the new one.</param>
    Task<ChangeEmailIssueResult> IssueAsync(
        long userId,
        string newEmail,
        string currentEmail,
        string callerConfirmUrl,
        TimeSpan ttl,
        bool invalidatePrevious,
        CancellationToken ct = default);

    /// <summary>
    /// Verifies and atomically consumes a change-of-e-mail token keyed by <paramref name="jti"/>.
    /// On success the row is marked <c>Consumed</c> and the bound user id + new/current
    /// snapshots are returned so the caller can apply the race-guard and atomic swap.
    /// </summary>
    Task<ChangeEmailVerifyResult> VerifyAndConsumeAsync(
        Guid jti,
        string token,
        CancellationToken ct = default);
}

/// <summary>Result of <see cref="IChangeEmailTokenStore.IssueAsync"/>.</summary>
public readonly record struct ChangeEmailIssueResult(
    Guid Jti,
    string PlaintextToken,
    DateTimeOffset ExpiresAt);

/// <summary>Result of <see cref="IChangeEmailTokenStore.VerifyAndConsumeAsync"/>.</summary>
/// <param name="Success">Whether the token verified AND the row was successfully consumed.</param>
/// <param name="UserId">Owner user id when <see cref="Success"/> is <c>true</c>; otherwise <c>0</c>.</param>
/// <param name="NewEmail">Lower-cased target address bound at issue time; empty when <see cref="Success"/> is <c>false</c>.</param>
/// <param name="CurrentEmail">Lower-cased snapshot of the e-mail at issue time; empty when <see cref="Success"/> is <c>false</c>.</param>
/// <param name="Reason">Diagnostic reason; values: <c>ok</c>, <c>not_found</c>, <c>expired</c>, <c>already_consumed</c>, <c>bad_token</c>.</param>
public readonly record struct ChangeEmailVerifyResult(
    bool Success,
    long UserId,
    string NewEmail,
    string CurrentEmail,
    string Reason);
