using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// B.3 — first-class role entity. Roles exist independently of groups and
/// claim mappers: they're a named bucket of access an operator can assign
/// to a user (directly) or to a group (transitively to every member).
///
/// <para>
/// Three layers in our token-issuance pipeline now compose orthogonally:
///   <list type="number">
///   <item><b>Claim mappers</b> (<see cref="ClaimMapperProps"/>) — declarative
///       rules that translate user attributes / group membership into JWT
///       claims at sign-in time. Mappers are the WIRING layer.</item>
///   <item><b>Groups</b> (<see cref="GroupProps"/>) — hierarchical user
///       organisation; can carry per-membership role labels via
///       <see cref="GroupMemberProps"/>. Groups are the MEMBERSHIP layer.</item>
///   <item><b>Roles</b> (this entity) — first-class named access buckets,
///       audience-scoped (organization-wide OR per-application). Assigned
///       directly to users via <see cref="UserRoleAssignmentProps"/> or
///       transitively via groups via <see cref="GroupRoleAssignmentProps"/>.
///       Roles are the ACCESS layer that operators reason about.</item>
///   </list>
/// </para>
///
/// <para>
/// Token issuance walks the user's EFFECTIVE role set = direct user
/// assignments ∪ transitive assignments via every group the user belongs to
/// (including ancestor groups when claim mappers expand the tree). For
/// audience='application' roles the set is FILTERED to the client_id of the
/// token being issued — an "engineering-admin" role on app A doesn't leak
/// into a token issued for app B.
/// </para>
///
/// <para>
/// Uniqueness: (Name, Audience, ApplicationId) is unique. Built-in roles
/// (system / everyone / admin / impersonator) are seeded with
/// <see cref="IsSystem"/>=true and can't be deleted via the admin API.
/// </para>
/// </summary>
[RedbScheme("identity.role")]
public class RoleProps
{
    /// <summary>
    /// Identifier-safe name; appears verbatim in the emitted <c>roles</c>
    /// claim. Convention: lowercase / hyphenated.
    /// </summary>
    public string Name { get; set; } = "";

    /// <summary>Operator-facing label rendered in the admin UI.</summary>
    public string? DisplayName { get; set; }

    public string? Description { get; set; }

    /// <summary>
    /// "organization" — visible to every application in this Identity
    /// instance; emitted on every token for which the user holds the role.
    /// "application" — scoped to a single application; emitted only on
    /// tokens issued for the matching <see cref="ApplicationId"/>.
    /// </summary>
    public string Audience { get; set; } = "organization";

    /// <summary>FK to the Application object id when <see cref="Audience"/> = "application". Null for organization.</summary>
    public long? ApplicationId { get; set; }

    /// <summary>
    /// True for system-seeded roles (system / everyone / admin / impersonator)
    /// — the admin API rejects delete on these. Set on the seed insert only;
    /// operator-created roles always have IsSystem=false.
    /// </summary>
    public bool IsSystem { get; set; }
}
