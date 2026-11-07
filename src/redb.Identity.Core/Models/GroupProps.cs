using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// PROPS entity for organizational groups with tree hierarchy.
/// Base fields used: name = display name, parent_id = parent group (tree), note = optional notes.
/// GroupType discriminates: "organization", "department", "team", "role".
/// </summary>
[RedbScheme("identity.group")]
public class GroupProps
{
    /// <summary>Group description.</summary>
    public string? Description { get; set; }

    /// <summary>"organization" | "department" | "team" | "role"</summary>
    public string? GroupType { get; set; }

    /// <summary>External identifier provided by SCIM clients (IdP-assigned).</summary>
    public string? ExternalId { get; set; }
}
