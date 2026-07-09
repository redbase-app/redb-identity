using System;
using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// N-4 (Session C): server-side material backing a single-use password-reset token.
/// <para>
/// The token plaintext (32 bytes of CSPRNG, base64url-encoded) is returned exactly once
/// from <c>IPasswordResetTokenStore.IssueAsync</c> for delivery via the e-mail channel;
/// what we persist is <c>sha256(pepper || token)</c> (lowercase hex) so a database leak
/// does not disclose live reset links. <see cref="Jti"/> is a per-issuance random
/// identifier carried on the reset URL alongside the plaintext so verify can locate the
/// row in O(1).
/// </para>
/// <para>
/// Consumption is single-use: <see cref="Consumed"/> flips to <c>true</c> atomically
/// under <c>LockForUpdate</c> during verify, and subsequent attempts against the same
/// <see cref="Jti"/> are rejected regardless of token correctness. Expired
/// (<see cref="ExpiresAt"/> &lt; now) or consumed rows are reaped by a periodic
/// cleanup route (analogous to <c>timer://identity-mfa-otp-cleanup</c>).
/// </para>
/// </summary>
[RedbScheme("identity.password_reset_token")]
public class PasswordResetTokenProps
{
    /// <summary>Random per-issuance identifier. Travels on the reset URL as <c>?jti=...</c>.</summary>
    public string Jti { get; set; } = "";

    /// <summary>Owner user id (joined to <c>_users</c>). Returned to the caller by verify.</summary>
    public long UserId { get; set; }

    /// <summary>
    /// <c>sha256(pepper || tokenPlaintext)</c>, lowercase hex. Never store plaintext.
    /// Pepper is supplied by <see cref="Services.RecoveryCodePepperProvider"/>.
    /// </summary>
    public string TokenHash { get; set; } = "";

    /// <summary>Issue timestamp (UTC).</summary>
    public DateTimeOffset IssuedAt { get; set; }

    /// <summary>Absolute expiry — verify requests after this instant fail regardless of token.</summary>
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>
    /// True once a successful verify has consumed the token. Mutated under <c>LockForUpdate</c>
    /// to enforce single-use semantics even under concurrent verify attempts.
    /// </summary>
    public bool Consumed { get; set; }

    /// <summary>
    /// Count of verify attempts (success+fail). Used by diagnostics and the cleanup route to
    /// surface abuse; not consulted directly for rate-limiting (that lives on the HTTP facade).
    /// </summary>
    public int Attempts { get; set; }

    /// <summary>
    /// The caller-supplied reset URL captured at issue time (the page that will host the
    /// reset form, e.g. <c>https://app.example.com/reset-password</c>). Recorded for audit
    /// and to enable optional cross-checks at verify time; the open-redirect / whitelist
    /// check itself is enforced at the HTTP facade against the configured allow-list.
    /// </summary>
    public string CallerResetUrl { get; set; } = "";
}
