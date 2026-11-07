using redb.Core.Models.Entities;
using redb.Identity.Core.Models;

namespace redb.Identity.Core.Services;

/// <summary>
/// Groups/RBAC service — manages hierarchical groups and flat memberships.
/// </summary>
public interface IGroupService
{
    // ── Group CRUD ──────────────────────────────────────────────

    Task<RedbObject<GroupProps>> CreateGroupAsync(
        string name, string? groupType = null, string? description = null,
        CancellationToken ct = default);

    Task<RedbObject<GroupProps>> CreateChildGroupAsync(
        long parentGroupId, string name, string? groupType = null, string? description = null,
        CancellationToken ct = default);

    Task<RedbObject<GroupProps>?> GetGroupAsync(long groupId, CancellationToken ct = default);

    Task UpdateGroupAsync(
        long groupId, string? name = null, string? groupType = null, string? description = null,
        CancellationToken ct = default);

    Task DeleteGroupAsync(long groupId, CancellationToken ct = default);

    // ── Tree operations ─────────────────────────────────────────

    Task<TreeRedbObject<GroupProps>> LoadTreeAsync(long rootGroupId, int? maxDepth = null, CancellationToken ct = default);

    Task<List<RedbObject<GroupProps>>> GetChildGroupsAsync(long parentGroupId, CancellationToken ct = default);

    Task<List<TreeRedbObject<GroupProps>>> GetPathToRootAsync(long groupId, CancellationToken ct = default);

    Task MoveGroupAsync(long groupId, long newParentGroupId, CancellationToken ct = default);

    Task<List<RedbObject<GroupProps>>> ListRootGroupsAsync(CancellationToken ct = default);

    /// <summary>
    /// B.2 — flat paginated search across ALL groups.
    /// </summary>
    Task<(List<RedbObject<GroupProps>> Items, int Total)> SearchGroupsAsync(
        string? namePattern, string? groupType, int offset, int count, CancellationToken ct = default);

    /// <summary>
    /// B.2 — bulk member-count for a set of groups, used to render the
    /// per-row badge on the groups list page without N round-trips.
    /// </summary>
    Task<Dictionary<long, int>> CountMembersByGroupAsync(
        IEnumerable<long> groupIds, CancellationToken ct = default);

    // ── Membership ──────────────────────────────────────────────

    Task<RedbObject<GroupMemberProps>> AddMemberAsync(
        long groupId, long userId, string? role = "member",
        DateTimeOffset? expiresAt = null, CancellationToken ct = default);

    /// <summary>
    /// Batch-add members to a group.
    /// Skips duplicates (existing memberships) without throwing.
    /// Uses AddNewObjectsAsync for bulk insert.
    /// </summary>
    Task AddMembersAsync(long groupId, IEnumerable<long> userIds, string? role = "member",
        CancellationToken ct = default);

    Task RemoveMemberAsync(long groupId, long userId, CancellationToken ct = default);

    /// <summary>
    /// Batch-remove members by userId. Single query + bulk delete.
    /// </summary>
    Task RemoveMembersAsync(long groupId, IEnumerable<long> userIds, CancellationToken ct = default);

    /// <summary>
    /// Remove all members of a group. Single query + bulk delete.
    /// </summary>
    Task RemoveAllMembersAsync(long groupId, CancellationToken ct = default);

    Task UpdateMemberRoleAsync(long groupId, long userId, string role, CancellationToken ct = default);

    Task<List<MemberInfo>> GetMembersAsync(long groupId, CancellationToken ct = default);

    /// <summary>
    /// Batch-load members for multiple groups in a single query.
    /// Returns a dictionary: groupId → list of active members.
    /// </summary>
    Task<Dictionary<long, List<MemberInfo>>> GetMembersByGroupIdsAsync(
        IEnumerable<long> groupIds, CancellationToken ct = default);

    Task<List<UserGroupInfo>> GetUserGroupsAsync(long userId, CancellationToken ct = default);

    Task<bool> IsMemberAsync(long groupId, long userId, CancellationToken ct = default);

    // ── Role resolution ─────────────────────────────────────────

    /// <summary>
    /// Returns all group names and roles for a user (active, non-expired memberships).
    /// Used by GroupClaimsResolver to populate token claims.
    /// </summary>
    Task<List<UserGroupInfo>> ResolveUserRolesAsync(long userId, CancellationToken ct = default);

    // ── DTOs ────────────────────────────────────────────────────

    public sealed class MemberInfo
    {
        public long MembershipId { get; init; }
        public long UserId { get; init; }
        public long GroupId { get; init; }
        public string? Role { get; init; }
        public DateTimeOffset? JoinedAt { get; init; }
        public DateTimeOffset? ExpiresAt { get; init; }
    }

    public sealed class UserGroupInfo
    {
        public long GroupId { get; init; }
        public string? GroupName { get; init; }
        public string? GroupType { get; init; }
        public string? Role { get; init; }
    }
}
