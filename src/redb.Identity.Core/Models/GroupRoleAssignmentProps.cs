using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// B.3 — group → role assignment. Every member of the group inherits the
/// role at token-issuance time; tree ancestors of the group don't
/// (assignments are NOT walked up the group hierarchy on purpose — the
/// group is the assignment scope, not the subtree).
///
/// <para>
/// Stored shape: <c>parent_id</c> = role's _objects.id, <c>value_long</c> =
/// group id, <c>key</c> = group id. Same uniqueness guarantees as
/// <see cref="UserRoleAssignmentProps"/>.
/// </para>
/// </summary>
[RedbScheme("identity.group_role_assignment")]
public class GroupRoleAssignmentProps
{
    public DateTimeOffset AssignedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Optional — id of the operator who assigned the role.</summary>
    public long? AssignedByUserId { get; set; }
}
