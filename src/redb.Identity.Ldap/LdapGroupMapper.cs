using System.Text;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Core.Query;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Route.Ldap;

namespace redb.Identity.Ldap;

/// <summary>
/// Syncs LDAP group memberships (memberOf attribute) to Identity groups.
/// Extracts CN from LDAP group DNs, auto-creates missing groups, and manages memberships.
/// </summary>
public sealed class LdapGroupMapper
{
    private readonly IGroupService _groupService;
    private readonly IRedbService _redb;
    private readonly LdapGroupMapperOptions _options;
    private readonly ILogger<LdapGroupMapper> _logger;
    private Dictionary<string, RedbObject<GroupProps>>? _groupCache;

    public LdapGroupMapper(
        IGroupService groupService,
        IRedbService redb,
        LdapGroupMapperOptions options,
        ILogger<LdapGroupMapper> logger)
    {
        _groupService = groupService ?? throw new ArgumentNullException(nameof(groupService));
        _redb = redb ?? throw new ArgumentNullException(nameof(redb));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Clears the group cache. Call after processing a sync batch.
    /// </summary>
    public void ClearGroupCache() => _groupCache = null;

    /// <summary>
    /// Syncs a user's group memberships from an LDAP entry's memberOf attribute.
    /// </summary>
    public async Task SyncUserGroupsAsync(long userId, LdapEntry entry, CancellationToken ct = default)
    {
        var memberOfValues = entry.GetStringArray(_options.GroupMemberAttribute);

        var ldapGroupNames = memberOfValues?
            .Select(ExtractCnFromDn)
            .Where(n => n is not null)
            .Cast<string>()
            .ToHashSet(StringComparer.OrdinalIgnoreCase)
            ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var currentMemberships = await _groupService.GetUserGroupsAsync(userId, ct).ConfigureAwait(false);

        foreach (var groupName in ldapGroupNames)
        {
            if (currentMemberships.Any(m => groupName.Equals(m.GroupName, StringComparison.OrdinalIgnoreCase)))
                continue;

            var group = await FindOrCreateGroupAsync(groupName!, ct).ConfigureAwait(false);
            if (group is null) continue;

            await _groupService.AddMemberAsync(group.id, userId, _options.MemberRole, ct: ct)
                .ConfigureAwait(false);

            _logger.LogInformation("Added user {UserId} to group '{GroupName}' (id={GroupId})",
                userId, groupName, group.id);
        }

        if (_options.SyncStrategy == LdapGroupSyncStrategy.Full)
        {
            foreach (var membership in currentMemberships)
            {
                if (membership.GroupName is null) continue;
                if (ldapGroupNames.Contains(membership.GroupName)) continue;

                await _groupService.RemoveMemberAsync(membership.GroupId, userId, ct)
                    .ConfigureAwait(false);

                _logger.LogInformation("Removed user {UserId} from group '{GroupName}' (id={GroupId})",
                    userId, membership.GroupName, membership.GroupId);
            }
        }
    }

    private async Task<RedbObject<GroupProps>?> FindOrCreateGroupAsync(string name, CancellationToken ct)
    {
        // Check cache first
        if (_groupCache?.TryGetValue(name, out var cached) == true)
            return cached;

        var existing = await _redb.Query<GroupProps>()
            .WhereRedb(o => o.Name == name)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);

        if (existing is not null)
        {
            (_groupCache ??= new(StringComparer.OrdinalIgnoreCase))[name] = existing;
            return existing;
        }

        if (!_options.AutoCreateGroups)
        {
            _logger.LogDebug("Group '{GroupName}' not found and AutoCreateGroups is disabled, skipping", name);
            return null;
        }

        _logger.LogInformation("Auto-creating group '{GroupName}' from LDAP memberOf", name);
        var created = await _groupService.CreateGroupAsync(name, groupType: "ldap", ct: ct)
            .ConfigureAwait(false);

        if (created is not null)
            (_groupCache ??= new(StringComparer.OrdinalIgnoreCase))[name] = created;

        return created;
    }

    /// <summary>
    /// Extracts the CN value from an LDAP distinguished name (RFC 4514).
    /// Handles escaped commas, quotes, and other special characters.
    /// "cn=Smith\, John,ou=groups,dc=test" → "Smith, John"
    /// </summary>
    internal static string? ExtractCnFromDn(string dn)
    {
        if (string.IsNullOrWhiteSpace(dn)) return null;

        if (!dn.StartsWith("cn=", StringComparison.OrdinalIgnoreCase))
            return null;

        var sb = new StringBuilder();
        for (int i = 3; i < dn.Length; i++)
        {
            if (dn[i] == '\\' && i + 1 < dn.Length)
            {
                sb.Append(dn[++i]);
                continue;
            }
            if (dn[i] == ',') break;
            sb.Append(dn[i]);
        }
        return sb.Length > 0 ? sb.ToString() : null;
    }
}

/// <summary>
/// Configuration for LDAP → Identity group sync.
/// </summary>
public sealed class LdapGroupMapperOptions
{
    /// <summary>LDAP attribute containing group DNs. Default: "memberOf".</summary>
    public string GroupMemberAttribute { get; set; } = "memberOf";

    /// <summary>Role assigned to synced memberships. Default: "member".</summary>
    public string MemberRole { get; set; } = "member";

    /// <summary>Auto-create Identity groups not yet in the system. Default: true.</summary>
    public bool AutoCreateGroups { get; set; } = true;

    /// <summary>Sync strategy. Full = add missing + remove extra. Additive = add only.</summary>
    public LdapGroupSyncStrategy SyncStrategy { get; set; } = LdapGroupSyncStrategy.Full;
}

/// <summary>Group membership sync strategy.</summary>
public enum LdapGroupSyncStrategy
{
    /// <summary>Bidirectional: add missing memberships, remove those not in LDAP.</summary>
    Full,

    /// <summary>Only add memberships from LDAP, never remove existing ones.</summary>
    Additive
}
