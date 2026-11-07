using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// B.3 (permission picker) — role → OAuth scope binding. One row per
/// (role, scope) pair. Drives the per-role permission set: every effective
/// role's attached scopes are unioned into the principal scope set at
/// token issuance, so a user inheriting role X automatically requests
/// scope orders.read when their token is minted.
///
/// <para>
/// Stored shape: <c>parent_id</c> = role's <c>_objects.id</c> (lets us list
/// every scope of a role in a single indexed scan), <c>value_long</c> +
/// <c>key</c> = scope's <c>_objects.id</c>. Same uniqueness pattern as
/// <c>UserRoleAssignmentProps</c>: idempotent attach (server-side dedupe by
/// (parent_id, key)) without a separate UNIQUE check.
/// </para>
/// </summary>
[RedbScheme("identity.role_scope_assignment")]
public class RoleScopeAssignmentProps
{
    public DateTimeOffset AttachedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Optional — id of the operator who attached the scope.</summary>
    public long? AttachedByUserId { get; set; }
}
