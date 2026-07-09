using redb.Core;
using redb.Core.Models.Entities;
using redb.Core.Query;
using redb.Identity.Core.Models;

namespace redb.Identity.Core.Services;

/// <summary>
/// B.3 — backing implementation for the Roles registry. All shapes go
/// through redb's native LINQ provider so cross-dialect (PG / MSSQL /
/// SQLite) works without per-driver SQL.
/// </summary>
public sealed class RoleService
{
    private readonly IRedbService _redb;

    public RoleService(IRedbService redb) => _redb = redb;

    // ── Role CRUD ──────────────────────────────────────────────

    public async Task<RedbObject<RoleProps>> CreateRoleAsync(
        string name, string audience, long? applicationId,
        string? displayName, string? description,
        bool isSystem = false,
        CancellationToken ct = default)
    {
        // Uniqueness check — (Name, Audience, ApplicationId)
        var dupe = await _redb.Query<RoleProps>()
            .Where(p => p.Name == name)
            .Where(p => p.Audience == audience)
            .Where(p => p.ApplicationId == applicationId)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);
        if (dupe is not null)
            throw new InvalidOperationException(
                $"Role '{name}' with audience '{audience}' (app={applicationId?.ToString() ?? "none"}) already exists.");

        var obj = new RedbObject<RoleProps>
        {
            name = name,
            Props = new RoleProps
            {
                Name = name,
                DisplayName = displayName,
                Description = description,
                Audience = audience,
                ApplicationId = applicationId,
                IsSystem = isSystem
            }
        };
        obj.id = await _redb.SaveAsync(obj).ConfigureAwait(false);
        return obj;
    }

    public async Task<RedbObject<RoleProps>?> GetRoleAsync(long roleId, CancellationToken ct = default)
        => await _redb.LoadAsync<RoleProps>(roleId).ConfigureAwait(false);

    public async Task UpdateRoleAsync(
        long roleId, string? displayName, string? description, CancellationToken ct = default)
    {
        var role = await _redb.LoadAsync<RoleProps>(roleId).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Role {roleId} not found.");

        if (displayName is not null) role.Props.DisplayName = displayName;
        if (description is not null) role.Props.Description = description;

        await _redb.SaveAsync(role).ConfigureAwait(false);
    }

    public async Task DeleteRoleAsync(long roleId, CancellationToken ct = default)
    {
        var role = await _redb.LoadAsync<RoleProps>(roleId).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Role {roleId} not found.");

        if (role.Props.IsSystem)
            throw new InvalidOperationException("System roles cannot be deleted.");

        // Cascade-clean assignments first so we don't leave orphaned rows
        // hanging around (foreign-key contract is parent_id → role id).
        await CleanAssignmentsAsync(roleId).ConfigureAwait(false);

        await _redb.DeleteAsync(role).ConfigureAwait(false);
    }

    /// <summary>
    /// Paged search across all roles, with optional name pattern + audience
    /// filter + application filter. Audience='application' + applicationId
    /// supplied narrows to one app's roles.
    /// </summary>
    public async Task<(List<RedbObject<RoleProps>> Items, int Total)> SearchRolesAsync(
        string? namePattern, string? audience, long? applicationId,
        int offset, int count, CancellationToken ct = default)
    {
        var query = _redb.Query<RoleProps>();
        if (!string.IsNullOrEmpty(namePattern))
        {
            var pat = namePattern;
            query = query.WhereRedb(o => o.Name.Contains(pat));
        }
        if (!string.IsNullOrEmpty(audience))
            query = query.Where(p => p.Audience == audience);
        if (applicationId is not null)
            query = query.Where(p => p.ApplicationId == applicationId);

        var total = (int)await query.CountAsync().ConfigureAwait(false);
        var items = await query
            .OrderByRedb(o => o.Name)
            .Skip(offset)
            .Take(count)
            .ToListAsync()
            .ConfigureAwait(false);
        return (items, total);
    }

    // ── Assignments ────────────────────────────────────────────

    public async Task AssignUserAsync(long roleId, long userId, long? actingUserId, CancellationToken ct = default)
    {
        // Idempotent — skip if row already exists with same role+user.
        var existing = await _redb.Query<UserRoleAssignmentProps>()
            .WhereRedb(o => o.ParentId == roleId)
            .WhereRedb(o => o.Key == userId)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);
        if (existing is not null) return;

        var obj = new RedbObject<UserRoleAssignmentProps>(new UserRoleAssignmentProps
        {
            AssignedAt = DateTimeOffset.UtcNow,
            AssignedByUserId = actingUserId
        })
        {
            name = $"user:{userId}",
            key = userId,
            parent_id = roleId,
            value_long = userId
        };
        await _redb.SaveAsync(obj).ConfigureAwait(false);
    }

    public async Task UnassignUserAsync(long roleId, long userId, CancellationToken ct = default)
    {
        var existing = await _redb.Query<UserRoleAssignmentProps>()
            .WhereRedb(o => o.ParentId == roleId)
            .WhereRedb(o => o.Key == userId)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);
        if (existing is null) return;
        await _redb.DeleteAsync(existing).ConfigureAwait(false);
    }

    public async Task AssignGroupAsync(long roleId, long groupId, long? actingUserId, CancellationToken ct = default)
    {
        var existing = await _redb.Query<GroupRoleAssignmentProps>()
            .WhereRedb(o => o.ParentId == roleId)
            .WhereRedb(o => o.Key == groupId)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);
        if (existing is not null) return;

        var obj = new RedbObject<GroupRoleAssignmentProps>(new GroupRoleAssignmentProps
        {
            AssignedAt = DateTimeOffset.UtcNow,
            AssignedByUserId = actingUserId
        })
        {
            name = $"group:{groupId}",
            key = groupId,
            parent_id = roleId,
            value_long = groupId
        };
        await _redb.SaveAsync(obj).ConfigureAwait(false);
    }

    public async Task UnassignGroupAsync(long roleId, long groupId, CancellationToken ct = default)
    {
        var existing = await _redb.Query<GroupRoleAssignmentProps>()
            .WhereRedb(o => o.ParentId == roleId)
            .WhereRedb(o => o.Key == groupId)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);
        if (existing is null) return;
        await _redb.DeleteAsync(existing).ConfigureAwait(false);
    }

    private async Task CleanAssignmentsAsync(long roleId)
    {
        var users = await _redb.Query<UserRoleAssignmentProps>()
            .WhereRedb(o => o.ParentId == roleId)
            .ToListAsync()
            .ConfigureAwait(false);
        foreach (var u in users) await _redb.DeleteAsync(u).ConfigureAwait(false);

        var groups = await _redb.Query<GroupRoleAssignmentProps>()
            .WhereRedb(o => o.ParentId == roleId)
            .ToListAsync()
            .ConfigureAwait(false);
        foreach (var g in groups) await _redb.DeleteAsync(g).ConfigureAwait(false);
    }

    // ── Queries (assignees + per-user role set) ────────────────

    /// <summary>
    /// Returns (userIds, groupIds) currently assigned to <paramref name="roleId"/>.
    /// </summary>
    public async Task<(List<long> UserIds, List<long> GroupIds)> ListAssigneesAsync(long roleId, CancellationToken ct = default)
    {
        var users = await _redb.Query<UserRoleAssignmentProps>()
            .WhereRedb(o => o.ParentId == roleId)
            .ToListAsync()
            .ConfigureAwait(false);
        var groups = await _redb.Query<GroupRoleAssignmentProps>()
            .WhereRedb(o => o.ParentId == roleId)
            .ToListAsync()
            .ConfigureAwait(false);
        return (
            users.Where(u => u.value_long.HasValue).Select(u => u.value_long!.Value).Distinct().ToList(),
            groups.Where(g => g.value_long.HasValue).Select(g => g.value_long!.Value).Distinct().ToList());
    }

    /// <summary>
    /// Bulk per-role assignment count for the list page badge.
    /// </summary>
    public async Task<Dictionary<long, int>> CountAssignmentsByRoleAsync(
        IEnumerable<long> roleIds, CancellationToken ct = default)
    {
        var ids = roleIds.Distinct().ToList();
        if (ids.Count == 0) return new();

        var users = await _redb.Query<UserRoleAssignmentProps>()
            .WhereInRedb(o => o.ParentId, ids.Cast<long?>())
            .ToListAsync()
            .ConfigureAwait(false);
        var groups = await _redb.Query<GroupRoleAssignmentProps>()
            .WhereInRedb(o => o.ParentId, ids.Cast<long?>())
            .ToListAsync()
            .ConfigureAwait(false);

        var counts = new Dictionary<long, int>();
        foreach (var u in users)
        {
            if (u.parent_id is { } pid) counts[pid] = counts.GetValueOrDefault(pid) + 1;
        }
        foreach (var g in groups)
        {
            if (g.parent_id is { } pid) counts[pid] = counts.GetValueOrDefault(pid) + 1;
        }
        return counts;
    }

    // ── Scope attachments ──────────────────────────────────────

    public async Task AttachScopeAsync(long roleId, long scopeId, long? actingUserId, CancellationToken ct = default)
    {
        var existing = await _redb.Query<RoleScopeAssignmentProps>()
            .WhereRedb(o => o.ParentId == roleId)
            .WhereRedb(o => o.Key == scopeId)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);
        if (existing is not null) return;

        var obj = new RedbObject<RoleScopeAssignmentProps>(new RoleScopeAssignmentProps
        {
            AttachedAt = DateTimeOffset.UtcNow,
            AttachedByUserId = actingUserId
        })
        {
            name = $"scope:{scopeId}",
            key = scopeId,
            parent_id = roleId,
            value_long = scopeId
        };
        await _redb.SaveAsync(obj).ConfigureAwait(false);
    }

    public async Task DetachScopeAsync(long roleId, long scopeId, CancellationToken ct = default)
    {
        var existing = await _redb.Query<RoleScopeAssignmentProps>()
            .WhereRedb(o => o.ParentId == roleId)
            .WhereRedb(o => o.Key == scopeId)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);
        if (existing is null) return;
        await _redb.DeleteAsync(existing).ConfigureAwait(false);
    }

    /// <summary>
    /// List scope IDs currently attached to <paramref name="roleId"/>.
    /// </summary>
    public async Task<List<long>> ListScopeIdsForRoleAsync(long roleId, CancellationToken ct = default)
    {
        var rows = await _redb.Query<RoleScopeAssignmentProps>()
            .WhereRedb(o => o.ParentId == roleId)
            .ToListAsync()
            .ConfigureAwait(false);
        return rows
            .Where(r => r.value_long.HasValue)
            .Select(r => r.value_long!.Value)
            .Distinct()
            .ToList();
    }

    /// <summary>
    /// Effective scope set for a set of roles — union of every role's
    /// attached scopes. Returns the SCOPE NAMES (string), ready to merge
    /// into the principal's scope list at token issuance.
    /// </summary>
    public async Task<HashSet<string>> GetEffectiveScopeNamesAsync(
        IEnumerable<long> roleIds, CancellationToken ct = default)
    {
        var ids = roleIds.Distinct().ToList();
        if (ids.Count == 0) return new(StringComparer.Ordinal);

        var rows = await _redb.Query<RoleScopeAssignmentProps>()
            .WhereInRedb(o => o.ParentId, ids.Cast<long?>())
            .ToListAsync()
            .ConfigureAwait(false);
        var scopeIds = rows
            .Where(r => r.value_long.HasValue)
            .Select(r => r.value_long!.Value)
            .Distinct()
            .ToList();
        if (scopeIds.Count == 0) return new(StringComparer.Ordinal);

        var scopes = await _redb.Query<ScopeProps>()
            .WhereInRedb(o => o.Id, scopeIds.Cast<long>())
            .ToListAsync()
            .ConfigureAwait(false);

        // ScopeProps.ScopeName has [RedbIgnore] — the canonical scope name is
        // stored in _objects.value_string (indexed) instead of in PROPS.
        return scopes
            .Select(s => s.value_string)
            .Where(n => !string.IsNullOrEmpty(n))
            .Select(n => n!)
            .ToHashSet(StringComparer.Ordinal);
    }

    /// <summary>
    /// Effective role set for a user at token issuance time:
    ///   direct user assignments ∪ assignments inherited from every group
    ///   the user belongs to. Filtered by audience and applicationId so an
    ///   audience='application' role bound to app A doesn't leak into a
    ///   token issued for app B.
    /// </summary>
    public async Task<List<RedbObject<RoleProps>>> GetEffectiveRolesAsync(
        long userId,
        IEnumerable<long> groupIds,
        long? applicationId,
        CancellationToken ct = default)
    {
        var groupIdList = groupIds.Distinct().ToList();

        // Direct user assignments → role ids
        var userAssignments = await _redb.Query<UserRoleAssignmentProps>()
            .WhereRedb(o => o.Key == userId)
            .ToListAsync()
            .ConfigureAwait(false);
        var roleIds = userAssignments
            .Where(u => u.parent_id.HasValue)
            .Select(u => u.parent_id!.Value)
            .ToHashSet();

        // Group → role ids
        if (groupIdList.Count > 0)
        {
            var groupAssignments = await _redb.Query<GroupRoleAssignmentProps>()
                .WhereInRedb(o => o.Key, groupIdList.Cast<long?>())
                .ToListAsync()
                .ConfigureAwait(false);
            foreach (var g in groupAssignments)
            {
                if (g.parent_id.HasValue) roleIds.Add(g.parent_id.Value);
            }
        }

        if (roleIds.Count == 0) return new();

        // Bulk-load the roles in one round trip, filter on audience.
        var roles = await _redb.Query<RoleProps>()
            .WhereInRedb(o => o.Id, roleIds.Cast<long>())
            .ToListAsync()
            .ConfigureAwait(false);

        return roles.Where(r =>
        {
            if (r.Props.Audience == "organization") return true;
            // audience='application' → only emit when applicationId matches.
            return applicationId.HasValue && r.Props.ApplicationId == applicationId.Value;
        }).ToList();
    }
}
