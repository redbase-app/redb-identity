using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// H5 (v1.0 DoD §5): Reusable named bundle of <see cref="ClaimMapperProps"/> rules.
/// <para>
/// Conceptually equivalent to Keycloak's <i>Client Scope</i>: an admin defines a scope
/// once (e.g. <c>"tenant_metadata"</c>) with a set of claim mappers attached via
/// <c>parent_id</c>, then assigns the scope to one or more applications via
/// <see cref="ClaimScopeAssignmentProps"/>. A token issued for an application gets
/// claims from: global mappers ∪ application-overlay mappers ∪ assigned-scopes mappers.
/// </para>
/// Base fields used: <c>name</c> = unique scope identifier (slug-like, indexed via
/// <c>value_string</c>).
/// </summary>
[RedbScheme("identity.claim_scope")]
public class ClaimScopeProps
{
    /// <summary>
    /// Unique scope identifier (slug). Stored in root <c>_objects.value_string</c>
    /// for indexed uniqueness lookup.
    /// </summary>
    [RedbIgnore]
    public string? ScopeName { get; set; }

    /// <summary>Free-form admin description.</summary>
    public string? Description { get; set; }

    /// <summary>
    /// When <c>false</c>, all assignments referencing this scope are inert — mappers under it
    /// are not applied. Allows soft-disable for incident response without unassigning.
    /// </summary>
    public bool Enabled { get; set; } = true;
}
