using System;
using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// N-4 (Session E, sub-step N4-7): server-side material backing a single-use
/// change-of-e-mail token. Carries both the requested <see cref="NewEmail"/> and a
/// snapshot of the user's e-mail at issue time (<see cref="CurrentEmail"/>) so the
/// confirm step can detect a race where the address was modified through another path
/// (admin update, /me/profile soft path, federation sync) between request and confirm.
/// </summary>
[RedbScheme("identity.change_email_token")]
public class ChangeEmailTokenProps
{
    /// <summary>Random per-issuance identifier. Travels on the confirm URL as <c>?jti=...</c>.</summary>
    public string Jti { get; set; } = "";

    /// <summary>Owner user id (joined to <c>_users</c>). Returned to the caller by verify.</summary>
    public long UserId { get; set; }

    /// <summary>
    /// Lower-cased copy of the address the user requested to switch <em>to</em>. Confirm
    /// writes this value into <c>_users.email</c> after passing the race-guards.
    /// </summary>
    public string NewEmail { get; set; } = "";

    /// <summary>
    /// Lower-cased snapshot of the user's e-mail at issue time. Confirm rejects the
    /// token when <c>_users.email != CurrentEmail</c> — defends against the address
    /// being changed concurrently by another path (admin, federation, soft /me path).
    /// </summary>
    public string CurrentEmail { get; set; } = "";

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
    /// True once a successful verify has consumed the token, OR when the row was
    /// invalidated by a fresh request (see <c>ChangeEmailOptions.InvalidatePreviousTokensOnRequest</c>).
    /// </summary>
    public bool Consumed { get; set; }

    /// <summary>Count of verify attempts (success+fail).</summary>
    public int Attempts { get; set; }

    /// <summary>
    /// Caller-supplied landing URL captured at issue time (the page that will host the
    /// confirm form). Recorded for audit; whitelist enforcement happens at the issuing
    /// processor against <c>ApplicationProps.ChangeEmailUris</c>.
    /// </summary>
    public string CallerConfirmUrl { get; set; } = "";
}
