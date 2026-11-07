using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// H5 (v1.0 DoD §5): Many-to-many link between an Application and a <see cref="ClaimScopeProps"/>.
/// <para>
/// Stored as a flat object (no tree relationship) so that adding / removing an assignment
/// is a single atomic write that does not perturb the application or scope objects.
/// Enforces uniqueness on <c>(ApplicationId, ScopeId)</c> through application-level check
/// (no compound partial index — uniqueness is rare-write, frequent-read).
/// </para>
/// Base fields used: <c>key</c> = ApplicationObjectId for fast indexed lookup of all
/// assignments for an application.
/// </summary>
[RedbScheme("identity.claim_scope_assignment")]
public class ClaimScopeAssignmentProps
{
    /// <summary>
    /// Application the scope is assigned to. Stored ALSO in <c>_objects.key</c> for indexed
    /// lookup; the PROPS field is the authoritative copy.
    /// </summary>
    public long ApplicationId { get; set; }

    /// <summary>Object id of the assigned <see cref="ClaimScopeProps"/>.</summary>
    public long ScopeId { get; set; }

    /// <summary>UTC timestamp the assignment was created.</summary>
    public DateTimeOffset AssignedAt { get; set; }

    /// <summary>Optional id of the admin user who created the assignment (for audit).</summary>
    public long? AssignedBy { get; set; }
}
