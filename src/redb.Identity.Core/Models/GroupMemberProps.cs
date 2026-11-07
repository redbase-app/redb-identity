using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// Flat membership link: key = userId, parent_id = groupId.
/// Role discriminates permissions within the group.
/// </summary>
[RedbScheme("identity.group_member")]
public class GroupMemberProps
{
    /// <summary>"owner" | "admin" | "member" | "viewer"</summary>
    public string? Role { get; set; }

    /// <summary>When the user joined the group.</summary>
    public DateTimeOffset? JoinedAt { get; set; }

    /// <summary>Optional TTL-based membership expiry.</summary>
    public DateTimeOffset? ExpiresAt { get; set; }
}
