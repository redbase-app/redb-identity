using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// B.3 — direct user → role assignment. One row per (user, role) pair.
///
/// <para>
/// Stored shape: <c>parent_id</c> points at the role's _objects.id (so we
/// can fetch every member of a role with a single Query.WhereRedb on
/// parent_id without joining); <c>value_long</c> mirrors the user id so the
/// reverse query (every role of a user) also runs as a single indexed
/// scan. The <c>key</c> field is also set to the user id, enabling a
/// per-scheme unique index on (parent_id, key) to enforce idempotent
/// assignment without a separate uniqueness check.
/// </para>
/// </summary>
[RedbScheme("identity.user_role_assignment")]
public class UserRoleAssignmentProps
{
    public DateTimeOffset AssignedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Optional — id of the operator who assigned the role.</summary>
    public long? AssignedByUserId { get; set; }
}
