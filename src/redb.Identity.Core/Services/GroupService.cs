using redb.Core;
using redb.Core.Extensions;
using redb.Core.Models.Contracts;
using redb.Core.Models.Entities;
using redb.Core.Services;
using redb.Identity.Core.Models;

namespace redb.Identity.Core.Services;

/// <summary>
/// Manages hierarchical groups (tree via parent_id) and flat memberships (GroupMemberProps).
/// </summary>
public sealed class GroupService : IGroupService
{
    private readonly IRedbService _redb;
    private readonly IBackgroundDeletionService? _backgroundDeletion;
    private readonly TimeProvider _timeProvider;

    public GroupService(IRedbService redb, IBackgroundDeletionService? backgroundDeletion = null)
        : this(redb, backgroundDeletion, TimeProvider.System)
    {
    }

    public GroupService(IRedbService redb, IBackgroundDeletionService? backgroundDeletion, TimeProvider? timeProvider)
    {
        _redb = redb;
        _backgroundDeletion = backgroundDeletion;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    // ── Group CRUD ──────────────────────────────────────────────

    public async Task<RedbObject<GroupProps>> CreateGroupAsync(
        string name, string? groupType = null, string? description = null,
        CancellationToken ct = default)
    {
        var obj = new RedbObject<GroupProps>
        {
            name = name,
            Props = new GroupProps
            {
                GroupType = groupType,
                Description = description
            }
        };

        obj.id = await _redb.SaveAsync(obj).ConfigureAwait(false);
        return obj;
    }

    public async Task<RedbObject<GroupProps>> CreateChildGroupAsync(
        long parentGroupId, string name, string? groupType = null, string? description = null,
        CancellationToken ct = default)
    {
        var parent = await _redb.LoadAsync<GroupProps>(parentGroupId).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Parent group {parentGroupId} not found.");

        var child = new TreeRedbObject<GroupProps>
        {
            name = name,
            Props = new GroupProps
            {
                GroupType = groupType,
                Description = description
            }
        };

        child.id = await _redb.CreateChildAsync(child, parent).ConfigureAwait(false);
        return child;
    }

    public async Task<RedbObject<GroupProps>?> GetGroupAsync(long groupId, CancellationToken ct = default)
    {
        var group = await _redb.LoadAsync<GroupProps>(groupId).ConfigureAwait(false);
        if (group is null || group.IsSoftDeleted()) return null;
        return group;
    }

    public async Task UpdateGroupAsync(
        long groupId, string? name = null, string? groupType = null, string? description = null,
        CancellationToken ct = default)
    {
        var group = await _redb.LoadAsync<GroupProps>(groupId).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Group {groupId} not found.");

        if (name is not null) group.name = name;
        if (groupType is not null) group.Props.GroupType = groupType;
        if (description is not null) group.Props.Description = description;

        await _redb.SaveAsync(group).ConfigureAwait(false);
    }

    public async Task DeleteGroupAsync(long groupId, CancellationToken ct = default)
    {
        // SoftDelete: marks group + all descendants with scheme = @@__deleted (-10).
        // No LoadAsync needed — works by ID, no FK cascade, instant return.
        var mark = await _redb.SoftDeleteAsync(new[] { groupId }).ConfigureAwait(false);

        // Enqueue background purge (physical deletion in batches) if available.
        _backgroundDeletion?.EnqueuePurge(mark.TrashId, mark.MarkedCount, 0);
    }

    // ── Tree operations ─────────────────────────────────────────

    public async Task<TreeRedbObject<GroupProps>> LoadTreeAsync(
        long rootGroupId, int? maxDepth = null, CancellationToken ct = default)
    {
        return await _redb.LoadTreeAsync<GroupProps>(rootGroupId, maxDepth).ConfigureAwait(false);
    }

    public async Task<List<RedbObject<GroupProps>>> GetChildGroupsAsync(
        long parentGroupId, CancellationToken ct = default)
    {
        var parent = await _redb.LoadAsync<GroupProps>(parentGroupId).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Group {parentGroupId} not found.");

        var children = await _redb.GetChildrenAsync<GroupProps>(parent).ConfigureAwait(false);
        return children.Cast<RedbObject<GroupProps>>().ToList();
    }

    public async Task<List<TreeRedbObject<GroupProps>>> GetPathToRootAsync(
        long groupId, CancellationToken ct = default)
    {
        var group = await _redb.LoadAsync<GroupProps>(groupId).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Group {groupId} not found.");

        var path = await _redb.GetPathToRootAsync<GroupProps>(group).ConfigureAwait(false);
        return path.ToList();
    }

    public async Task MoveGroupAsync(long groupId, long newParentGroupId, CancellationToken ct = default)
    {
        var group = await _redb.LoadAsync<GroupProps>(groupId).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Group {groupId} not found.");

        var newParent = await _redb.LoadAsync<GroupProps>(newParentGroupId).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Target parent group {newParentGroupId} not found.");

        await _redb.MoveObjectAsync(group, newParent).ConfigureAwait(false);
    }

    public async Task<List<RedbObject<GroupProps>>> ListRootGroupsAsync(CancellationToken ct = default)
    {
        return await _redb.Query<GroupProps>()
            .WhereRedb(o => o.ParentId == null)
            .ToListAsync()
            .ConfigureAwait(false);
    }

    /// <summary>
    /// B.2 — flat paginated search across ALL groups (root + nested),
    /// optionally filtered by name substring and groupType. Powers the
    /// `/admin/groups` list page where operators want to find a single
    /// group across a deeply nested tree without expanding nodes.
    /// </summary>
    public async Task<(List<RedbObject<GroupProps>> Items, int Total)> SearchGroupsAsync(
        string? namePattern,
        string? groupType,
        int offset,
        int count,
        CancellationToken ct = default)
    {
        var query = _redb.Query<GroupProps>();
        if (!string.IsNullOrEmpty(namePattern))
        {
            var pat = namePattern;
            query = query.WhereRedb(o => o.Name.Contains(pat));
        }
        if (!string.IsNullOrEmpty(groupType))
        {
            var gt = groupType;
            query = query.Where(p => p.GroupType == gt);
        }
        var total = (int)await query.CountAsync().ConfigureAwait(false);
        var items = await query
            .OrderByRedb(o => o.Name)
            .Skip(offset)
            .Take(count)
            .ToListAsync()
            .ConfigureAwait(false);
        return (items, total);
    }

    /// <summary>
    /// Bulk-count members per group — drives the per-row member-count badge
    /// on the groups list page without N round-trips.
    /// </summary>
    public async Task<Dictionary<long, int>> CountMembersByGroupAsync(
        IEnumerable<long> groupIds,
        CancellationToken ct = default)
    {
        var ids = groupIds.Distinct().ToList();
        if (ids.Count == 0) return new();
        var rows = await _redb.Query<GroupMemberProps>()
            .WhereInRedb(o => o.ParentId, ids.Cast<long?>())
            .ToListAsync()
            .ConfigureAwait(false);
        return rows
            .Where(r => r.parent_id.HasValue)
            .GroupBy(r => r.parent_id!.Value)
            .ToDictionary(g => g.Key, g => g.Count());
    }

    // ── Membership ──────────────────────────────────────────────

    public async Task<RedbObject<GroupMemberProps>> AddMemberAsync(
        long groupId, long userId, string? role = "member",
        DateTimeOffset? expiresAt = null, CancellationToken ct = default)
    {
        _ = await _redb.LoadAsync<GroupProps>(groupId).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Group {groupId} not found.");

        var existing = await _redb.Query<GroupMemberProps>()
            .WhereRedb(o => o.Key == userId && o.ParentId == groupId)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);

        if (existing is not null)
            throw new InvalidOperationException($"User {userId} is already a member of group {groupId}.");

        var member = new RedbObject<GroupMemberProps>
        {
            key = userId,
            parent_id = groupId,
            Props = new GroupMemberProps
            {
                Role = role,
                JoinedAt = _timeProvider.GetUtcNow(),
                ExpiresAt = expiresAt
            }
        };

        member.id = await _redb.SaveAsync(member).ConfigureAwait(false);
        return member;
    }

    public async Task AddMembersAsync(
        long groupId, IEnumerable<long> userIds, string? role = "member",
        CancellationToken ct = default)
    {
        var idList = userIds.ToList();
        if (idList.Count == 0) return;

        // Single query: find existing memberships to skip duplicates
        var nullableGroupId = (long?)groupId;
        var existingKeys = (await _redb.Query<GroupMemberProps>()
            .WhereRedb(o => o.ParentId == nullableGroupId)
            .ToListAsync().ConfigureAwait(false))
            .Where(m => m.key.HasValue)
            .Select(m => m.key!.Value)
            .ToHashSet();

        var now = _timeProvider.GetUtcNow();
        var toAdd = idList
            .Where(uid => !existingKeys.Contains(uid))
            .Select(uid => (IRedbObject<GroupMemberProps>)new RedbObject<GroupMemberProps>
            {
                key = uid,
                parent_id = groupId,
                Props = new GroupMemberProps { Role = role, JoinedAt = now }
            })
            .ToList();

        if (toAdd.Count > 0)
            await _redb.AddNewObjectsAsync(toAdd).ConfigureAwait(false);
    }

    public async Task RemoveMemberAsync(long groupId, long userId, CancellationToken ct = default)
    {
        var member = await _redb.Query<GroupMemberProps>()
            .WhereRedb(o => o.Key == userId && o.ParentId == groupId)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException($"User {userId} is not a member of group {groupId}.");

        await IdentityDeletionHelper.DeleteAsync(_redb, _backgroundDeletion, member).ConfigureAwait(false);
    }

    public async Task RemoveMembersAsync(long groupId, IEnumerable<long> userIds, CancellationToken ct = default)
    {
        var idSet = userIds.ToHashSet();
        if (idSet.Count == 0) return;

        var nullableGroupId = (long?)groupId;
        var members = await _redb.Query<GroupMemberProps>()
            .WhereRedb(o => o.ParentId == nullableGroupId)
            .ToListAsync().ConfigureAwait(false);

        var toRemove = members.Where(m => m.key.HasValue && idSet.Contains(m.key.Value)).ToList();
        if (toRemove.Count > 0)
            await IdentityDeletionHelper.DeleteAsync(_redb, _backgroundDeletion, toRemove).ConfigureAwait(false);
    }

    public async Task RemoveAllMembersAsync(long groupId, CancellationToken ct = default)
    {
        var nullableGroupId = (long?)groupId;
        var members = await _redb.Query<GroupMemberProps>()
            .WhereRedb(o => o.ParentId == nullableGroupId)
            .ToListAsync().ConfigureAwait(false);

        if (members.Count > 0)
            await IdentityDeletionHelper.DeleteAsync(_redb, _backgroundDeletion, members).ConfigureAwait(false);
    }

    public async Task UpdateMemberRoleAsync(
        long groupId, long userId, string role, CancellationToken ct = default)
    {
        var member = await _redb.Query<GroupMemberProps>()
            .WhereRedb(o => o.Key == userId && o.ParentId == groupId)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException($"User {userId} is not a member of group {groupId}.");

        member.Props.Role = role;
        await _redb.SaveAsync(member).ConfigureAwait(false);
    }

    public async Task<List<IGroupService.MemberInfo>> GetMembersAsync(
        long groupId, CancellationToken ct = default)
    {
        var now = _timeProvider.GetUtcNow();
        var members = await _redb.Query<GroupMemberProps>()
            .WhereRedb(o => o.ParentId == groupId)
            .Where(m => m.ExpiresAt == null || m.ExpiresAt >= now)
            .ToListAsync()
            .ConfigureAwait(false);

        return members
            .Select(m => new IGroupService.MemberInfo
            {
                MembershipId = m.id,
                UserId = m.key ?? 0,
                GroupId = groupId,
                Role = m.Props.Role,
                JoinedAt = m.Props.JoinedAt,
                ExpiresAt = m.Props.ExpiresAt
            }).ToList();
    }

    public async Task<Dictionary<long, List<IGroupService.MemberInfo>>> GetMembersByGroupIdsAsync(
        IEnumerable<long> groupIds, CancellationToken ct = default)
    {
        var idList = groupIds.ToList();
        if (idList.Count == 0)
            return new Dictionary<long, List<IGroupService.MemberInfo>>();

        var now = _timeProvider.GetUtcNow();
        var nullableIds = idList.Select(id => (long?)id).ToList();
        var allMembers = await _redb.Query<GroupMemberProps>()
            .WhereRedb(o => nullableIds.Contains(o.ParentId))
            .ToListAsync()
            .ConfigureAwait(false);

        var result = idList.ToDictionary(id => id, _ => new List<IGroupService.MemberInfo>());

        foreach (var m in allMembers)
        {
            if (m.Props.ExpiresAt.HasValue && m.Props.ExpiresAt.Value < now)
                continue;

            var gid = m.parent_id ?? 0;
            if (result.TryGetValue(gid, out var list))
            {
                list.Add(new IGroupService.MemberInfo
                {
                    MembershipId = m.id,
                    UserId = m.key ?? 0,
                    GroupId = gid,
                    Role = m.Props.Role,
                    JoinedAt = m.Props.JoinedAt,
                    ExpiresAt = m.Props.ExpiresAt
                });
            }
        }

        return result;
    }

    public async Task<List<IGroupService.UserGroupInfo>> GetUserGroupsAsync(
        long userId, CancellationToken ct = default)
    {
        var now = _timeProvider.GetUtcNow();
        var memberships = await _redb.Query<GroupMemberProps>()
            .WhereRedb(o => o.Key == userId)
            .Where(m => m.ExpiresAt == null || m.ExpiresAt >= now)
            .ToListAsync()
            .ConfigureAwait(false);

        return await EnrichWithGroupInfo(memberships).ConfigureAwait(false);
    }

    public async Task<bool> IsMemberAsync(long groupId, long userId, CancellationToken ct = default)
    {
        // Check direct membership first
        var member = await _redb.Query<GroupMemberProps>()
            .WhereRedb(o => o.Key == userId && o.ParentId == groupId)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);

        if (member is not null)
        {
            if (!member.Props.ExpiresAt.HasValue || member.Props.ExpiresAt.Value >= _timeProvider.GetUtcNow())
                return true;
        }

        // Ancestor traversal: check if user is member of any ancestor group.
        // Server-side: one path-to-root load + ONE batched WhereInRedb across all
        // ancestor parent_ids (instead of N round-trips, one per ancestor).
        var group = await _redb.LoadAsync<GroupProps>(groupId).ConfigureAwait(false);
        if (group is null) return false;

        var path = await _redb.GetPathToRootAsync<GroupProps>(group).ConfigureAwait(false);
        var ancestorIds = path
            .Select(a => (long?)a.id)
            .Where(id => id != groupId)
            .ToList();

        if (ancestorIds.Count == 0) return false;

        var now = _timeProvider.GetUtcNow();
        var ancestorMemberships = await _redb.Query<GroupMemberProps>()
            .WhereRedb(o => o.Key == userId)
            .WhereInRedb(o => o.ParentId, ancestorIds)
            .Where(m => m.ExpiresAt == null || m.ExpiresAt >= now)
            .AnyAsync()
            .ConfigureAwait(false);

        return ancestorMemberships;
    }

    // ── Role resolution ─────────────────────────────────────────

    public async Task<List<IGroupService.UserGroupInfo>> ResolveUserRolesAsync(
        long userId, CancellationToken ct = default)
    {
        var now = _timeProvider.GetUtcNow();
        var memberships = await _redb.Query<GroupMemberProps>()
            .WhereRedb(o => o.Key == userId)
            .Where(m => m.ExpiresAt == null || m.ExpiresAt >= now)
            .ToListAsync()
            .ConfigureAwait(false);

        return await EnrichWithGroupInfo(memberships).ConfigureAwait(false);
    }

    // ── Helpers ──────────────────────────────────────────────────

    private async Task<List<IGroupService.UserGroupInfo>> EnrichWithGroupInfo(
        List<RedbObject<GroupMemberProps>> memberships)
    {
        if (memberships.Count == 0)
            return [];

        // Batch-load all referenced groups in ONE query to avoid N+1 round-trips
        // — a user with many group memberships otherwise turned this admin enrichment
        // into an O(N) round-trip storm.
        var groupIds = memberships
            .Where(m => m.parent_id.HasValue)
            .Select(m => m.parent_id!.Value)
            .Distinct()
            .ToArray();

        var groups = new Dictionary<long, RedbObject<GroupProps>>(groupIds.Length);
        if (groupIds.Length > 0)
        {
            var loaded = await _redb.Query<GroupProps>()
                .WhereInRedb(o => o.Id, groupIds)
                .ToListAsync()
                .ConfigureAwait(false);

            foreach (var g in loaded)
                groups[g.id] = g;
        }

        return memberships.Select(m =>
        {
            groups.TryGetValue(m.parent_id ?? 0, out var g);
            return new IGroupService.UserGroupInfo
            {
                GroupId = m.parent_id ?? 0,
                GroupName = g?.name,
                GroupType = g?.Props.GroupType,
                Role = m.Props.Role
            };
        }).ToList();
    }
}
