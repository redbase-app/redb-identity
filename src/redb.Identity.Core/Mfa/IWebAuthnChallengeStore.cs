using System.Threading;
using System.Threading.Tasks;

namespace redb.Identity.Core.Mfa;

/// <summary>
/// MFA-3: server-side single-use marker for consumed WebAuthn challenges.
/// <para>
/// Closes the replay window between challenge issuance and natural TTL expiry. The challenge
/// itself is encrypted into the client-facing setup-token / mfa_state for convenience (no
/// DB hit on issue), but completion of the ceremony writes a row here, and a second
/// completion attempt with the same challenge fails fast with <c>replay_detected</c>.
/// </para>
/// <para>
/// We persist only the SHA-256 hash of the challenge bytes — sufficient for equality on
/// consume, no exposure of live challenges if the DB is leaked. Atomicity guaranteed by
/// the calling transaction: <c>WebAuthnMfaMethod.Complete*Async</c> writes this row in the
/// same TX as the credential persistence (registration) or sign-counter advance (assertion).
/// </para>
/// </summary>
public interface IWebAuthnChallengeStore
{
    /// <summary>
    /// Atomically marks a challenge as consumed by the given user for the given operation.
    /// <list type="bullet">
    ///   <item><description>Returns <see cref="WebAuthnConsumeResult.Ok"/> on first consume.</description></item>
    ///   <item><description>Returns <see cref="WebAuthnConsumeResult.Replay"/> if a row with the same hash already exists.</description></item>
    /// </list>
    /// </summary>
    /// <param name="challenge">Raw challenge bytes (32 random bytes per ceremony).</param>
    /// <param name="userId">Owner of the ceremony.</param>
    /// <param name="operation"><c>register</c> or <c>assert</c>.</param>
    /// <param name="ttl">How long to keep the consumed marker before cleanup may delete it.</param>
    Task<WebAuthnConsumeResult> ConsumeAsync(
        byte[] challenge,
        long userId,
        string operation,
        TimeSpan ttl,
        CancellationToken ct = default);
}

/// <summary>Result of <see cref="IWebAuthnChallengeStore.ConsumeAsync"/>.</summary>
public enum WebAuthnConsumeResult
{
    /// <summary>Challenge consumed for the first time — ceremony may proceed.</summary>
    Ok,

    /// <summary>Challenge has already been consumed — reject as replay.</summary>
    Replay,
}
