using System.Text.Json;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Core.Query;
using redb.Core.Services;
using redb.Identity.Contracts.Scim;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.RedbCore.Extensions;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// SCIM 2.0 Groups endpoint processor (RFC 7644 §3.2–3.5).
/// Dispatches on "operation" header: list, read, create, replace, patch, delete.
/// Maps SCIM Group resources to PROPS <see cref="GroupProps"/> via <see cref="IGroupService"/>.
/// </summary>
internal sealed class ScimGroupProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;
    private readonly ILogger? _logger;
    private readonly IBackgroundDeletionService? _backgroundDeletion;

    public ScimGroupProcessor(IRouteContext context, string? redbName = null, ILogger? logger = null,
        IBackgroundDeletionService? backgroundDeletion = null)
    {
        _context = context;
        _redbName = redbName;
        _logger = logger;
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
            case "list":    await List(svc, redb, exchange, ct); break;
            case "read":    await Read(svc, redb, exchange, ct); break;
            case "create":  await Create(svc, redb, exchange, ct); break;
            case "replace": await Replace(svc, redb, exchange, ct); break;
            case "patch":   await Patch(svc, redb, exchange, ct); break;
            case "delete":  await Delete(svc, exchange, ct); break;
            default:
                SetScimError(exchange, 400, null, $"Unknown SCIM operation: {operation}");
                break;
        }
    }

    // ── List (GET /Groups) ──────────────────────────────────────

    private static string GetBaseUrl(IExchange exchange)
        => exchange.In.GetHeader<string>("scim.BaseUrl") ?? string.Empty;

    private static async Task List(IGroupService svc, IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        var baseUrl = GetBaseUrl(exchange);
        var dict = exchange.In.Body as Dictionary<string, object?> ?? new();
        var startIndex = GetInt(dict, "startIndex", 1);
        var count = Math.Min(GetInt(dict, "count", 25), 100);
        var filterStr = dict.GetValueOrDefault("filter")?.ToString();
        var sortBy = dict.GetValueOrDefault("sortBy")?.ToString();
        var sortOrder = dict.GetValueOrDefault("sortOrder")?.ToString();

        var filter = ScimFilterParser.Parse(filterStr);

        // ── Filtered queries (displayName only) ──
        if (filter is not null)
        {
            if (filter.Attribute != "displayname")
            {
                SetScimError(exchange, 400, "invalidFilter",
                    $"Unsupported filter attribute: {filter.Attribute}. Supported: displayName");
                return;
            }

            // Build base query with filter
            IRedbQueryable<GroupProps> q;

            switch (filter.Operator)
            {
                case "eq":
                    q = redb.Query<GroupProps>()
                        .WhereRedb(o => o.ParentId == null && o.Name == filter.Value);
                    break;
                case "ne":
                    q = redb.Query<GroupProps>()
                        .WhereRedb(o => o.ParentId == null && o.Name != filter.Value);
                    break;
                case "sw":
                    q = redb.Query<GroupProps>()
                        .WhereRedb(o => o.ParentId == null && o.Name.StartsWith(filter.Value));
                    break;
                case "co":
                    q = redb.Query<GroupProps>()
                        .WhereRedb(o => o.ParentId == null && o.Name.Contains(filter.Value));
                    break;
                case "pr":
                    // displayName pr — all groups have a name, return all
                    q = redb.Query<GroupProps>()
                        .WhereRedb(o => o.ParentId == null);
                    break;
                default:
                    SetScimError(exchange, 400, "invalidFilter",
                        $"Unsupported operator: {filter.Operator}. Supported: eq, ne, sw, co, pr");
                    return;
            }

            // Total before pagination
            var filteredTotal = await q.CountAsync();

            // Apply sort + pagination
            var filteredOffset = Math.Max(startIndex - 1, 0);
            var ordered = ApplyGroupSort(q, sortBy, sortOrder);
            var matched = await ordered.Skip(filteredOffset).Take(count).ToListAsync();

            var filteredMembersByGroup = await svc.GetMembersByGroupIdsAsync(
                matched.Select(g => g.id), ct);

            var resources = new List<ScimGroup>(matched.Count);
            foreach (var g in matched)
            {
                filteredMembersByGroup.TryGetValue(g.id, out var members);
                resources.Add(await MapToScimGroup(g, members, redb, baseUrl));
            }

            SetResult(exchange, new ScimListResponse<ScimGroup>
            {
                TotalResults = filteredTotal, StartIndex = startIndex,
                ItemsPerPage = resources.Count, Resources = resources
            });
            return;
        }

        // ── No filter → server-side paginated query ──
        var baseQ = redb.Query<GroupProps>()
            .WhereRedb(o => o.ParentId == null);
        var total = await baseQ.CountAsync();
        var offset = Math.Max(startIndex - 1, 0);
        var orderedBase = ApplyGroupSort(baseQ, sortBy, sortOrder);
        var page = await orderedBase.Skip(offset).Take(count).ToListAsync();

        var membersByGroup = await svc.GetMembersByGroupIdsAsync(
            page.Select(g => g.id), ct);

        var scimGroups = new List<ScimGroup>(page.Count);
        foreach (var g in page)
        {
            membersByGroup.TryGetValue(g.id, out var members);
            scimGroups.Add(await MapToScimGroup(g, members, redb, baseUrl));
        }

        SetResult(exchange, new ScimListResponse<ScimGroup>
        {
            TotalResults = total,
            StartIndex = startIndex,
            ItemsPerPage = scimGroups.Count,
            Resources = scimGroups
        });
    }

    // ── Read (GET /Groups/{id}) ─────────────────────────────────

    private static async Task Read(IGroupService svc, IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        var id = ExtractResourceId(exchange);
        if (id is null) { SetScimError(exchange, 400, null, "Resource id is required"); return; }

        var group = await svc.GetGroupAsync(id.Value, ct);
        if (group is null) { SetScimError(exchange, 404, null, $"Group {id} not found"); return; }

        var members = await svc.GetMembersAsync(id.Value, ct);
        SetResult(exchange, await MapToScimGroup(group, members, redb, GetBaseUrl(exchange)));
        SetETagHeader(exchange, group.hash);
    }

    // ── Create (POST /Groups) ───────────────────────────────────

    private static async Task Create(IGroupService svc, IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        var scimGroup = exchange.In.Body as ScimGroup;
        if (scimGroup is null || string.IsNullOrEmpty(scimGroup.DisplayName))
        {
            SetScimError(exchange, 400, null, "displayName is required");
            return;
        }

        var group = await svc.CreateGroupAsync(scimGroup.DisplayName, "scim", null, ct);

        // I8: Store SCIM externalId as PROPS prop
        if (!string.IsNullOrEmpty(scimGroup.ExternalId))
        {
            group.Props ??= new GroupProps();
            group.Props.ExternalId = scimGroup.ExternalId;
            await redb.SaveAsync(group);
        }

        // Add initial members if provided (batch)
        if (scimGroup.Members is { Count: > 0 })
        {
            var memberIds = scimGroup.Members
                .Select(m => long.TryParse(m.Value, out var uid) && uid > 0 ? uid : 0)
                .Where(uid => uid > 0).ToList();
            if (memberIds.Count > 0)
                await svc.AddMembersAsync(group.id, memberIds, "member", ct);
        }

        var members = await svc.GetMembersAsync(group.id, ct);
        SetResult(exchange, await MapToScimGroup(group, members, redb, GetBaseUrl(exchange)));

        // I1: RFC 7644 §3.3 — return 201 Created with Location header
        exchange.Out!.Headers["scim.ResponseCode"] = 201;
        exchange.Out!.Headers["scim.Location"] = $"/scim/v2/Groups/{group.id}";
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ScimGroupCreated;
        exchange.Properties["identity-event-data"] = new { GroupId = group.id, Name = scimGroup.DisplayName };
    }

    // ── Replace (PUT /Groups/{id}) ──────────────────────────────

    private static async Task Replace(
        IGroupService svc, IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        var scimGroup = exchange.In.Body as ScimGroup;
        if (scimGroup is null || string.IsNullOrEmpty(scimGroup.Id))
        {
            SetScimError(exchange, 400, null, "Resource id and body are required");
            return;
        }

        if (!long.TryParse(scimGroup.Id, out var id) || id <= 0)
        {
            SetScimError(exchange, 400, null, "Invalid resource id");
            return;
        }

        var existing = await svc.GetGroupAsync(id, ct);
        if (existing is null) { SetScimError(exchange, 404, null, $"Group {id} not found"); return; }

        // ETag precondition check
        if (!CheckIfMatch(exchange, existing.hash)) return;

        // Update group name
        await svc.UpdateGroupAsync(id, scimGroup.DisplayName, null, null, ct);

        // I8: Update SCIM externalId
        var reloaded = await svc.GetGroupAsync(id, ct);
        if (reloaded is not null)
        {
            reloaded.Props ??= new GroupProps();
            reloaded.Props.ExternalId = scimGroup.ExternalId; // null clears it
            await redb.SaveAsync(reloaded);
        }

        // Replace members: batch remove + batch add
        await svc.RemoveAllMembersAsync(id, ct);

        if (scimGroup.Members is { Count: > 0 })
        {
            var memberIds = scimGroup.Members
                .Select(m => long.TryParse(m.Value, out var uid) && uid > 0 ? uid : 0)
                .Where(uid => uid > 0).ToList();
            if (memberIds.Count > 0)
                await svc.AddMembersAsync(id, memberIds, "member", ct);
        }

        var updatedGroup = await svc.GetGroupAsync(id, ct);
        var updatedMembers = await svc.GetMembersAsync(id, ct);
        SetResult(exchange, await MapToScimGroup(updatedGroup!, updatedMembers, redb, GetBaseUrl(exchange)));
        SetETagHeader(exchange, updatedGroup?.hash);

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ScimGroupReplaced;
        exchange.Properties["identity-event-data"] = new { GroupId = id };
    }

    // ── Patch (PATCH /Groups/{id}) ──────────────────────────────

    private static async Task Patch(
        IGroupService svc, IRedbService redb, IExchange exchange, CancellationToken ct)
    {
        if (exchange.In.Body is not Dictionary<string, object?> dict)
        {
            SetScimError(exchange, 400, null, "Invalid patch request");
            return;
        }

        var idStr = dict.GetValueOrDefault("id")?.ToString();
        if (!long.TryParse(idStr, out var id) || id <= 0)
        {
            SetScimError(exchange, 400, null, "Resource id is required");
            return;
        }

        var patch = dict.GetValueOrDefault("patch") as ScimPatchRequest;
        if (patch is null || patch.Operations.Count == 0)
        {
            SetScimError(exchange, 400, null, "PatchOp request with Operations is required");
            return;
        }

        var group = await svc.GetGroupAsync(id, ct);
        if (group is null) { SetScimError(exchange, 404, null, $"Group {id} not found"); return; }

        // ETag precondition check
        if (!CheckIfMatch(exchange, group.hash)) return;

        foreach (var op in patch.Operations)
        {
            var normalizedOp = op.Op?.ToLowerInvariant();
            var path = op.Path?.ToLowerInvariant();

            switch (path)
            {
                case "displayname":
                    if (normalizedOp is "add" or "replace")
                    {
                        var newName = GetStringValue(op.Value);
                        if (newName is not null)
                            await svc.UpdateGroupAsync(id, newName, null, null, ct);
                    }
                    break;

                case "externalid":
                    if (normalizedOp is "add" or "replace")
                    {
                        var extId = GetStringValue(op.Value);
                        group.Props ??= new GroupProps();
                        group.Props.ExternalId = extId;
                        await redb.SaveAsync(group);
                    }
                    else if (normalizedOp is "remove")
                    {
                        group.Props ??= new GroupProps();
                        group.Props.ExternalId = null;
                        await redb.SaveAsync(group);
                    }
                    break;

                case "members":
                    if (normalizedOp is "add")
                    {
                        // Batch-add members from value array
                        await AddMembersFromValue(svc, id, op.Value, ct);
                    }
                    else if (normalizedOp is "replace")
                    {
                        // Batch replace: remove all + batch add
                        await svc.RemoveAllMembersAsync(id, ct);
                        await AddMembersFromValue(svc, id, op.Value, ct);
                    }
                    else if (normalizedOp is "remove")
                    {
                        // Batch remove all members
                        await svc.RemoveAllMembersAsync(id, ct);
                    }
                    break;

                default:
                    // Check for members[value eq "userId"] path (Azure Entra pattern)
                    if (path is not null && path.StartsWith("members["))
                    {
                        var memberId = ExtractMemberFilterId(path);
                        if (memberId is not null)
                        {
                            if (normalizedOp is "remove")
                            {
                                try { await svc.RemoveMemberAsync(id, memberId.Value, ct); }
                                catch (InvalidOperationException) { /* already removed */ }
                            }
                        }
                    }
                    break;
            }
        }

        var updatedGroup = await svc.GetGroupAsync(id, ct);
        var members = await svc.GetMembersAsync(id, ct);
        SetResult(exchange, await MapToScimGroup(updatedGroup!, members, redb, GetBaseUrl(exchange)));
        SetETagHeader(exchange, updatedGroup?.hash);

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ScimGroupPatched;
        exchange.Properties["identity-event-data"] = new { GroupId = id };
    }

    // ── Delete (DELETE /Groups/{id}) ────────────────────────────

    private static async Task Delete(IGroupService svc, IExchange exchange, CancellationToken ct)
    {
        var id = ExtractResourceId(exchange);
        if (id is null) { SetScimError(exchange, 400, null, "Resource id is required"); return; }

        var group = await svc.GetGroupAsync(id.Value, ct);
        if (group is null) { SetScimError(exchange, 404, null, $"Group {id} not found"); return; }

        // ETag precondition check
        if (!CheckIfMatch(exchange, group.hash)) return;

        await svc.DeleteGroupAsync(id.Value, ct);

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = null;

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ScimGroupDeleted;
        exchange.Properties["identity-event-data"] = new { GroupId = id.Value };
    }

    // ── Mapping ─────────────────────────────────────────────────

    private static async Task<ScimGroup> MapToScimGroup(
        RedbObject<GroupProps> group,
        List<IGroupService.MemberInfo>? members = null,
        IRedbService? redb = null,
        string? baseUrl = null)
    {
        var scimGroup = new ScimGroup
        {
            Id = group.id.ToString(),
            ExternalId = group.Props?.ExternalId,
            DisplayName = group.name,
            Meta = new ScimMeta
            {
                ResourceType = "Group",
                Created = group.date_create,
                LastModified = group.date_modify,
                Location = $"{baseUrl}/scim/v2/Groups/{group.id}",
                Version = group.hash.HasValue ? $"W/\"{group.hash.Value}\"" : null
            }
        };

        if (members is { Count: > 0 })
        {
            // I7+I4: Batch-load user display names in a single query
            Dictionary<long, string?> displayNames = new();
            if (redb is not null)
            {
                var memberIds = members.Select(m => m.UserId);
                var users = await redb.UserProvider.GetUsersByIdsAsync(memberIds);
                foreach (var u in users)
                    displayNames[u.Id] = u.Name;
            }

            scimGroup.Members = new List<ScimMemberRef>(members.Count);
            foreach (var m in members)
            {
                displayNames.TryGetValue(m.UserId, out var display);
                scimGroup.Members.Add(new ScimMemberRef
                {
                    Value = m.UserId.ToString(),
                    Display = display,
                    Ref = $"{baseUrl}/scim/v2/Users/{m.UserId}"
                });
            }
        }

        return scimGroup;
    }

    // ── PATCH helpers ───────────────────────────────────────────

    private static async Task AddMembersFromValue(
        IGroupService svc, long groupId, JsonElement? value, CancellationToken ct)
    {
        if (value is null) return;

        var userIds = new List<long>();
        if (value.Value.ValueKind == JsonValueKind.Array)
        {
            foreach (var elem in value.Value.EnumerateArray())
            {
                if (elem.TryGetProperty("value", out var v)
                    && long.TryParse(v.GetString(), out var userId) && userId > 0)
                    userIds.Add(userId);
            }
        }
        else if (value.Value.ValueKind == JsonValueKind.Object)
        {
            if (value.Value.TryGetProperty("value", out var v)
                && long.TryParse(v.GetString(), out var userId) && userId > 0)
                userIds.Add(userId);
        }

        if (userIds.Count > 0)
            await svc.AddMembersAsync(groupId, userIds, "member", ct);
    }

    /// <summary>
    /// Extracts userId from path like <c>members[value eq "123"]</c>.
    /// Azure Entra sends PATCH remove with this path pattern.
    /// </summary>
    private static long? ExtractMemberFilterId(string path)
    {
        // members[value eq "123"]
        var match = System.Text.RegularExpressions.Regex.Match(
            path, @"members\[value\s+eq\s+""(\d+)""\]",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);

        if (match.Success && long.TryParse(match.Groups[1].Value, out var id))
            return id;
        return null;
    }

    // ── Helpers ─────────────────────────────────────────────────

    private static long? ExtractResourceId(IExchange exchange)
    {
        if (exchange.In.Body is Dictionary<string, object?> dict
            && dict.TryGetValue("id", out var idVal) && idVal is not null
            && long.TryParse(idVal.ToString(), out var id) && id > 0)
            return id;
        return null;
    }

    private static string? GetStringValue(JsonElement? value)
    {
        if (value is null) return null;
        return value.Value.ValueKind == JsonValueKind.String
            ? value.Value.GetString()
            : value.Value.GetRawText();
    }

    private static void SetScimError(IExchange exchange, int status, string? scimType, string? detail)
    {
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new ScimError
        {
            Status = status.ToString(),
            ScimType = scimType,
            Detail = detail
        };
    }

    private static void SetResult(IExchange exchange, object body)
    {
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = body;
    }

    private static int GetInt(Dictionary<string, object?> dict, string key, int defaultValue)
    {
        if (dict.TryGetValue(key, out var val) && val is not null
            && int.TryParse(val.ToString(), out var result))
            return result;
        return defaultValue;
    }

    /// <summary>
    /// Applies SCIM sortBy/sortOrder to a group query. Defaults to Name ascending.
    /// </summary>
    private static IRedbQueryable<GroupProps> ApplyGroupSort(
        IRedbQueryable<GroupProps> query, string? sortBy, string? sortOrder)
    {
        bool desc = string.Equals(sortOrder, "descending", StringComparison.OrdinalIgnoreCase);
        return (sortBy?.ToLowerInvariant()) switch
        {
            "id" => desc ? query.OrderByDescendingRedb(x => x.Id) : query.OrderByRedb(x => x.Id),
            "meta.created" => desc ? query.OrderByDescendingRedb(x => x.DateCreate) : query.OrderByRedb(x => x.DateCreate),
            "meta.lastmodified" => desc ? query.OrderByDescendingRedb(x => x.DateModify) : query.OrderByRedb(x => x.DateModify),
            _ => desc ? query.OrderByDescendingRedb(x => x.Name) : query.OrderByRedb(x => x.Name),
        };
    }

    private static bool CheckIfMatch(IExchange exchange, Guid? currentHash)
    {
        var ifMatch = exchange.In.GetHeader<string>("scim.IfMatch");
        if (string.IsNullOrEmpty(ifMatch)) return true;
        if (ifMatch == "*") return true;

        var expected = ifMatch.Replace("W/", "").Trim('"');
        var actual = currentHash?.ToString();

        if (!string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase))
        {
            SetScimError(exchange, 412, null, "ETag precondition failed — resource has been modified");
            return false;
        }
        return true;
    }

    private static void SetETagHeader(IExchange exchange, Guid? hash)
    {
        if (hash.HasValue)
            exchange.Out!.Headers["scim.ETag"] = $"W/\"{hash.Value}\"";
    }
}
