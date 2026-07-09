using System;
using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// N-4 (Session C, sub-step N4-6): server-side material backing a single-use
/// e-mail-verification token. Mirror of <see cref="PasswordResetTokenProps"/> with one
/// extra field — <see cref="Email"/> — that binds the token to a specific e-mail value
/// captured at issue time. Confirm only flips <c>UserProps.EmailVerified = true</c> when
/// the user's current e-mail still matches this snapshot (defends against the
/// double-change race where a token issued for value A is consumed after the user has
/// already pivoted to value B).
/// </summary>
[RedbScheme("identity.email_verification_token")]
public class EmailVerificationTokenProps
{
    /// <summary>Random per-issuance identifier. Travels on the verify URL as <c>?jti=...</c>.</summary>
    public string Jti { get; set; } = "";

    /// <summary>Owner user id (joined to <c>_users</c>). Returned to the caller by verify.</summary>
    public long UserId { get; set; }

    /// <summary>
    /// Lower-cased snapshot of the user's e-mail at issue time. Confirm rejects the token
    /// when <c>_users.email != Email</c> at consumption — this prevents a stale link from
    /// vouching for a new address the user has since adopted.
    /// </summary>
    public string Email { get; set; } = "";

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
    /// Count of verify attempts (success+fail). Used by diagnostics and the cleanup route.
    /// </summary>
    public int Attempts { get; set; }

    /// <summary>
    /// The caller-supplied landing URL captured at issue time (the page that will host
    /// the verify-confirmation, e.g. <c>https://app.example.com/verify-email</c>).
    /// Recorded for audit; whitelist enforcement happens at issue time against
    /// <c>ApplicationProps.EmailVerifyUris</c>.
    /// </summary>
    public string CallerVerifyUrl { get; set; } = "";
}
