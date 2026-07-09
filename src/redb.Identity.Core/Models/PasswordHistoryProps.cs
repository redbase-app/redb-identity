using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// H10 — per-user password history entry. Stores a verifier-hash (Argon2id by default,
/// produced via the same <see cref="redb.Core.Security.IPasswordHasher"/> that hashes
/// live credentials) of a previously-used password so that
/// <see cref="Configuration.PasswordPolicyOptions.HistoryCount"/> recent passwords can be
/// rejected on reuse. Plain-text passwords are NEVER persisted.
/// <para>
/// Each row is owned by the user whose password it tracks; soft-delete cascades on user
/// removal happen via the standard <c>IdentityDeletionHelper</c> flow (rows are soft-
/// deleted alongside <see cref="UserProps"/>).
/// </para>
/// </summary>
[RedbScheme("identity.password_history")]
public class PasswordHistoryProps
{
    /// <summary>Owner user id (foreign key to <c>_users._id</c>).</summary>
    public long UserId { get; set; }

    /// <summary>Argon2id (or legacy) verifier-hash of the previously-used password.</summary>
    public string HashedPassword { get; set; } = "";

    /// <summary>UTC timestamp when this password became the user's active credential.</summary>
    public DateTimeOffset CreatedAt { get; set; }
}
