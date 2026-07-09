using redb.Core.Services;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.RedbCore.Extensions;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// Group management processor — dispatches on "operation" header.
/// Operations: list, read, create, create-child, update, delete, move,
///   tree, path, children, list-members, add-member, update-member, remove-member,
///   user-groups, is-member.
/// </summary>
internal sealed class GroupManagementProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;
    private readonly IBackgroundDeletionService? _backgroundDeletion;

    public GroupManagementProcessor(IRouteContext context, string? redbName = null,
        IBackgroundDeletionService? backgroundDeletion = null)
    {
        _context = context;
        _redbName = redbName;
        _backgroundDeletion = backgroundDeletion;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var redb = _context.GetRedbService(_redbName, exchange);
        var svc = new GroupService(redb, _backgroundDeletion);
        var operation = exchange.In.GetHeader<string>("operation")
            ?? throw new InvalidOperationException("Missing 'operation' header");

        switch (operation)
        {
            case "list":           await ListRoots(svc, exchange, ct); break;
            case "search":         await Search(svc, exchange, ct); break;
            case "read":           await Read(svc, exchange, ct); break;
            case "create":         await Create(svc, exchange, ct); break;
            case "create-child":   await CreateChild(svc, exchange, ct); break;
            case "update":         await Update(svc, exchange, ct); break;
            case "delete":         await Delete(svc, exchange, ct); break;
            case "move":           await Move(svc, exchange, ct); break;
            case "tree":           await Tree(svc, exchange, ct); break;
            case "path":           await Path(svc, exchange, ct); break;
            case "list-members":   await ListMembers(svc, exchange, ct); break;
            case "add-member":     await AddMember(svc, exchange, ct); break;
            case "update-member":  await UpdateMember(svc, exchange, ct); break;
            case "remove-member":  await RemoveMember(svc, exchange, ct); break;
            case "children":       await Children(svc, exchange, ct); break;
            case "is-member":      await IsMember(svc, exchange, ct); break;
            case "user-groups":    await UserGroups(svc, exchange, ct); break;
            default:
                SetError(exchange, "invalid_operation", $"Unknown operation: {operation}");
                break;
        }
    }

    // ── Group CRUD ──────────────────────────────────────────────

    private static async Task ListRoots(IGroupService svc, IExchange exchange, CancellationToken ct)
    {
        var groups = await svc.ListRootGroupsAsync(ct);
        SetResult(exchange, groups.Select(g => MapGroup(g)).ToList());
    }

    private static async Task Search(IGroupService svc, IExchange exchange, CancellationToken ct)
    {
        var dict = exchange.In.Body as Dictionary<string, object?> ?? new();

        string? query = dict.TryGetValue("query", out var q) ? q?.ToString() : null;
        string? groupType = dict.TryGetValue("groupType", out var t) ? t?.ToString() : null;
        var offset = 0;
        var count = 25;
        if (dict.TryGetValue("offset", out var oVal) && int.TryParse(oVal?.ToString(), out var parsedOff))
            offset = Math.Max(0, parsedOff);
        if (dict.TryGetValue("count", out var cVal) && int.TryParse(cVal?.ToString(), out var parsedCount))
            count = Math.Clamp(parsedCount, 1, 200);

        var (items, total) = await svc.SearchGroupsAsync(
            string.IsNullOrWhiteSpace(query) ? null : query,
            string.IsNullOrWhiteSpace(groupType) ? null : groupType,
            offset, count, ct).ConfigureAwait(false);

        // One bulk member-count query for every visible row (vs N round-trips
        // if the UI did "list then count each").
        var counts = await svc.CountMembersByGroupAsync(items.Select(i => i.Id), ct).ConfigureAwait(false);

        SetResult(exchange, new redb.Identity.Contracts.Common.PagedResult<object>
        {
            Items = items.Select(g => MapGroupWithMembers(g, counts.GetValueOrDefault(g.Id, 0))).ToList(),
            Total = total,
            Offset = offset,
            Count = count
        });
    }

    private static async Task Read(IGroupService svc, IExchange exchange, CancellationToken ct)
    {
        var id = IdentityProcessorHelpers.ExtractRequiredLong(exchange, "groupId");
        var group = await svc.GetGroupAsync(id, ct);
        if (group is null) { SetError(exchange, "not_found", $"Group {id} not found"); return; }
        SetResult(exchange, MapGroup(group));
    }

    private static async Task Create(IGroupService svc, IExchange exchange, CancellationToken ct)
    {
        var dict = RequireBody(exchange);
        var name = dict.GetValueOrDefault("name")?.ToString()
            ?? throw new InvalidOperationException("name is required");
        var groupType = dict.GetValueOrDefault("groupType")?.ToString();
        var description = dict.GetValueOrDefault("description")?.ToString();

        var group = await svc.CreateGroupAsync(name, groupType, description, ct);
        SetResult(exchange, MapGroup(group));
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.GroupCreated;
        exchange.Properties["identity-event-data"] = new { GroupId = group.id, Name = name };
    }

    private static async Task CreateChild(IGroupService svc, IExchange exchange, CancellationToken ct)
    {
        var dict = RequireBody(exchange);
        var parentId = IdentityProcessorHelpers.ExtractLong(dict, "parentGroupId")
            ?? throw new InvalidOperationException("parentGroupId is required");
        var name = dict.GetValueOrDefault("name")?.ToString()
            ?? throw new InvalidOperationException("name is required");
        var groupType = dict.GetValueOrDefault("groupType")?.ToString();
        var description = dict.GetValueOrDefault("description")?.ToString();

        var group = await svc.CreateChildGroupAsync(parentId, name, groupType, description, ct);
        SetResult(exchange, MapGroup(group));
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.GroupCreated;
        exchange.Properties["identity-event-data"] = new { GroupId = group.id, ParentGroupId = parentId, Name = name };
    }

    private static async Task Update(IGroupService svc, IExchange exchange, CancellationToken ct)
    {
        var dict = RequireBody(exchange);
        var id = IdentityProcessorHelpers.ExtractLong(dict, "groupId")
            ?? IdentityProcessorHelpers.ExtractRequiredLong(exchange, "groupId");
        var name = dict.GetValueOrDefault("name")?.ToString();
        var groupType = dict.GetValueOrDefault("groupType")?.ToString();
        var description = dict.GetValueOrDefault("description")?.ToString();

        await svc.UpdateGroupAsync(id, name, groupType, description, ct);
        SetResult(exchange, new { success = true, groupId = id });
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.GroupUpdated;
        exchange.Properties["identity-event-data"] = new { GroupId = id };
    }

    private static async Task Delete(IGroupService svc, IExchange exchange, CancellationToken ct)
    {
        var id = IdentityProcessorHelpers.ExtractRequiredLong(exchange, "groupId");
        await svc.DeleteGroupAsync(id, ct);
        SetResult(exchange, new { success = true, groupId = id });
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.GroupDeleted;
        exchange.Properties["identity-event-data"] = new { GroupId = id };
    }

    // ── Tree operations ─────────────────────────────────────────

    private static async Task Move(IGroupService svc, IExchange exchange, CancellationToken ct)
    {
        var dict = RequireBody(exchange);
        var id = IdentityProcessorHelpers.ExtractLong(dict, "groupId")
            ?? IdentityProcessorHelpers.ExtractRequiredLong(exchange, "groupId");
        var newParentId = IdentityProcessorHelpers.ExtractLong(dict, "newParentGroupId")
            ?? throw new InvalidOperationException("newParentGroupId is required");

        await svc.MoveGroupAsync(id, newParentId, ct);
        SetResult(exchange, new { success = true, groupId = id, newParentGroupId = newParentId });
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.GroupMoved;
        exchange.Properties["identity-event-data"] = new { GroupId = id, NewParentGroupId = newParentId };
    }

    private static async Task Tree(IGroupService svc, IExchange exchange, CancellationToken ct)
    {
        var id = IdentityProcessorHelpers.ExtractRequiredLong(exchange, "groupId");
        int? maxDepth = null;
        if (exchange.In.Body is Dictionary<string, object?> dict
            && dict.TryGetValue("maxDepth", out var md) && md is not null
            && int.TryParse(md.ToString(), out var d))
            maxDepth = d;

        var tree = await svc.LoadTreeAsync(id, maxDepth, ct);
        SetResult(exchange, MapTreeNode(tree));
    }

    private static async Task Path(IGroupService svc, IExchange exchange, CancellationToken ct)
    {
        var id = IdentityProcessorHelpers.ExtractRequiredLong(exchange, "groupId");
        var path = await svc.GetPathToRootAsync(id, ct);
        SetResult(exchange, path.Select(g => MapGroup(g)).ToList());
    }

    // ── Membership ──────────────────────────────────────────────

    private static async Task ListMembers(IGroupService svc, IExchange exchange, CancellationToken ct)
    {
        var groupId = IdentityProcessorHelpers.ExtractRequiredLong(exchange, "groupId");
        var members = await svc.GetMembersAsync(groupId, ct);
        SetResult(exchange, members);
    }

    private static async Task AddMember(IGroupService svc, IExchange exchange, CancellationToken ct)
    {
        var dict = RequireBody(exchange);
        var groupId = IdentityProcessorHelpers.ExtractLong(dict, "groupId")
            ?? IdentityProcessorHelpers.ExtractRequiredLong(exchange, "groupId");
        var userId = IdentityProcessorHelpers.ExtractLong(dict, "userId")
            ?? throw new InvalidOperationException("userId is required");
        var role = dict.GetValueOrDefault("role")?.ToString() ?? "member";

        DateTimeOffset? expiresAt = null;
        if (dict.TryGetValue("expiresAt", out var ea) && ea is not null
            && DateTimeOffset.TryParse(ea.ToString(), out var parsed))
            expiresAt = parsed;

        var member = await svc.AddMemberAsync(groupId, userId, role, expiresAt, ct);
        SetResult(exchange, new { success = true, membershipId = member.id, groupId, userId, role });
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.MemberAdded;
        exchange.Properties["identity-event-data"] = new { GroupId = groupId, UserId = userId, Role = role };
    }

    private static async Task UpdateMember(IGroupService svc, IExchange exchange, CancellationToken ct)
    {
        var dict = RequireBody(exchange);
        var groupId = IdentityProcessorHelpers.ExtractLong(dict, "groupId")
            ?? IdentityProcessorHelpers.ExtractRequiredLong(exchange, "groupId");
        var userId = IdentityProcessorHelpers.ExtractLong(dict, "userId")
            ?? throw new InvalidOperationException("userId is required");
        var role = dict.GetValueOrDefault("role")?.ToString()
            ?? throw new InvalidOperationException("role is required");

        await svc.UpdateMemberRoleAsync(groupId, userId, role, ct);
        SetResult(exchange, new { success = true, groupId, userId, role });
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.MemberUpdated;
        exchange.Properties["identity-event-data"] = new { GroupId = groupId, UserId = userId, Role = role };
    }

    private static async Task RemoveMember(IGroupService svc, IExchange exchange, CancellationToken ct)
    {
        var dict = RequireBody(exchange);
        var groupId = IdentityProcessorHelpers.ExtractLong(dict, "groupId")
            ?? IdentityProcessorHelpers.ExtractRequiredLong(exchange, "groupId");
        var userId = IdentityProcessorHelpers.ExtractLong(dict, "userId")
            ?? throw new InvalidOperationException("userId is required");

        await svc.RemoveMemberAsync(groupId, userId, ct);
        SetResult(exchange, new { success = true, groupId, userId });
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.MemberRemoved;
        exchange.Properties["identity-event-data"] = new { GroupId = groupId, UserId = userId };
    }

    private static async Task UserGroups(IGroupService svc, IExchange exchange, CancellationToken ct)
    {
        var userId = IdentityProcessorHelpers.ExtractRequiredLong(exchange, "userId");
        var groups = await svc.GetUserGroupsAsync(userId, ct);
        SetResult(exchange, groups);
    }

    private static async Task Children(IGroupService svc, IExchange exchange, CancellationToken ct)
    {
        var groupId = IdentityProcessorHelpers.ExtractRequiredLong(exchange, "groupId");
        var children = await svc.GetChildGroupsAsync(groupId, ct);
        SetResult(exchange, children.Select(g => MapGroup(g)).ToList());
    }

    private static async Task IsMember(IGroupService svc, IExchange exchange, CancellationToken ct)
    {
        var dict = RequireBody(exchange);
        var groupId = IdentityProcessorHelpers.ExtractLong(dict, "groupId")
            ?? IdentityProcessorHelpers.ExtractRequiredLong(exchange, "groupId");
        var userId = IdentityProcessorHelpers.ExtractLong(dict, "userId")
            ?? throw new InvalidOperationException("userId is required");

        var result = await svc.IsMemberAsync(groupId, userId, ct);
        SetResult(exchange, new { isMember = result, groupId, userId });
    }

    // ── Helpers ─────────────────────────────────────────────────

    private static Dictionary<string, object?> RequireBody(IExchange exchange)
        => exchange.In.Body as Dictionary<string, object?>
            ?? throw new InvalidOperationException("Body is required");

    private static void SetResult(IExchange exchange, object body)
    {
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = body;
    }

    private static void SetError(IExchange exchange, string error, string description)
        => IdentityProcessorHelpers.SetError(exchange, error, description);

    private static object MapGroup(redb.Core.Models.Entities.RedbObject<GroupProps> g) => new
    {
        id = g.id,
        name = g.name,
        parentId = g.parent_id,
        groupType = g.Props.GroupType,
        description = g.Props.Description,
        createdAt = g.date_create,
        modifiedAt = g.date_modify
    };

    private static object MapGroupWithMembers(redb.Core.Models.Entities.RedbObject<GroupProps> g, int memberCount) => new
    {
        id = g.id,
        name = g.name,
        parentId = g.parent_id,
        groupType = g.Props.GroupType,
        description = g.Props.Description,
        createdAt = g.date_create,
        modifiedAt = g.date_modify,
        memberCount = memberCount
    };

    private static object MapTreeNode(redb.Core.Models.Entities.TreeRedbObject<GroupProps> node) => new
    {
        id = node.id,
        name = node.name,
        parentId = node.parent_id,
        groupType = node.Props.GroupType,
        description = node.Props.Description,
        level = node.Level,
        children = node.Children
            .OfType<redb.Core.Models.Entities.TreeRedbObject<GroupProps>>()
            .Select(c => MapTreeNode(c))
            .ToList()
    };
}
