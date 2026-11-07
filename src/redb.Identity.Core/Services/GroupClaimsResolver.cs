using System.Security.Claims;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using redb.Core;
using redb.Core.Models.Contracts;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace redb.Identity.Core.Services;

/// <summary>
/// Enriches a <see cref="ClaimsPrincipal"/> with group/role claims
/// when the corresponding scopes ("groups", "roles") are requested.
/// </summary>
public sealed class GroupClaimsResolver
{
    public const string GroupsScope = "groups";
    public const string RolesScope = "roles";
    public const string GroupsClaim = "groups";
    public const string RolesClaim = "roles";
    public const string OrgClaim = "org";

    private readonly IGroupService _groupService;
    private readonly IRedbService? _redb;
    private readonly ILogger<GroupClaimsResolver>? _logger;

    public GroupClaimsResolver(IGroupService groupService, ILogger<GroupClaimsResolver>? logger = null)
    {
        _groupService = groupService;
        _redb = null;
        _logger = logger;
    }

    public GroupClaimsResolver(IRedbService redb, ILogger<GroupClaimsResolver>? logger = null)
    {
        _redb = redb;
        _groupService = new GroupService(redb);
        _logger = logger;
    }

    /// <summary>
    /// Adds group names and/or role names to the principal's identity
    /// based on requested scopes.
    /// </summary>
    /// <remarks>
    /// Group claims include both direct memberships AND ancestor groups via tree-hierarchy
    /// (composite group inheritance — DoD §5 H2). For example, if user is in "developers"
    /// which is a child of "engineering" which is a child of "company", the principal
    /// receives <c>groups: ["developers", "engineering", "company"]</c>. Ancestor expansion
    /// uses a single server-side recursive CTE (via <c>TreeQuery + ToTreeListAsync</c>) —
    /// not an N+1 client-side walk — so it scales to deep / wide group hierarchies.
    /// The <c>org</c> claim also walks the tree to find the closest organization-type
    /// ancestor when no direct organization-type membership exists. Per-membership
    /// <c>Role</c> labels (<see cref="RolesClaim"/>) are NOT inherited — they describe
    /// the user's role within a specific group, not a transitive concept.
    /// </remarks>
    public async Task EnrichPrincipalAsync(
        ClaimsPrincipal principal,
        long userId,
        IEnumerable<string> scopes,
        CancellationToken ct = default)
    {
        var scopeList = scopes as IReadOnlyList<string> ?? scopes.ToList();
        var needGroups = scopeList.Contains(GroupsScope);
        var needRoles = scopeList.Contains(RolesScope);

        if (!needGroups && !needRoles)
            return;

        var identity = principal.Identity as ClaimsIdentity;
        if (identity is null)
            return;

        var userGroups = await _groupService.GetUserGroupsAsync(userId, ct).ConfigureAwait(false);

        if (needGroups)
        {
            // Step 1: collect direct group names + walk tree ancestors for inherited groups.
            // Deduped by name (HashSet) — same group may be ancestor of multiple direct
            // memberships, and case-sensitive uniqueness is intentional (group names are
            // typically slug-like identifiers, not display labels).
            var allGroupNames = new HashSet<string>(StringComparer.Ordinal);
            string? inheritedOrg = null;

            foreach (var ug in userGroups)
            {
                if (!string.IsNullOrEmpty(ug.GroupName))
                    allGroupNames.Add(ug.GroupName!);
            }

            // Step 2: server-side ancestor expansion via single recursive CTE round-trip.
            // TreeQuery + ToTreeListAsync internally calls GetIdsWithAncestorsAsync (one
            // recursive CTE) and LoadObjectsByIdsAsync (one batched load), avoiding the
            // N+1 pattern of per-membership GetPathToRootAsync calls. Falls back to
            // per-membership ancestor walk only when _redb is unavailable (legacy ctor).
            var directIds = userGroups
                .Where(g => g.GroupId > 0)
                .Select(g => g.GroupId)
                .Distinct()
                .ToList();

            if (directIds.Count > 0)
            {
                if (_redb is not null)
                {
                    List<TreeRedbObject<GroupProps>> directNodes;
                    try
                    {
                        directNodes = await _redb
                            .TreeQuery<GroupProps>()
                            .WhereInRedb(o => o.Id, directIds)
                            .ToTreeListAsync()
                            .ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        // Ancestor expansion failure must not 500 the token endpoint —
                        // the principal still gets direct-membership groups + roles,
                        // which is enough for most authorisation flows. Logged so an
                        // operator can see the regression even when degraded.
                        _logger?.LogWarning(ex,
                            "GroupClaimsResolver: TreeQuery ancestor expansion failed for groups [{Ids}] — falling back to direct-only group names",
                            string.Join(",", directIds));
                        directNodes = new List<TreeRedbObject<GroupProps>>();
                    }

                    foreach (var direct in directNodes)
                    {
                        // Walk parent chain — parents already materialized in-memory via
                        // ToTreeListAsync's recursive CTE, no further round-trips needed.
                        ITreeRedbObject? node = direct.Parent;
                        while (node is not null)
                        {
                            if (!string.IsNullOrEmpty(node.Name))
                                allGroupNames.Add(node.Name);

                            // Track first organization-type ancestor for fallback org claim.
                            if (inheritedOrg is null
                                && node is TreeRedbObject<GroupProps> typed
                                && string.Equals(typed.Props?.GroupType, "organization", StringComparison.OrdinalIgnoreCase)
                                && !string.IsNullOrEmpty(typed.name))
                            {
                                inheritedOrg = typed.name;
                            }

                            node = node.Parent;
                        }
                    }
                }
                else
                {
                    // Legacy fallback: per-membership ancestor walk (used only when
                    // resolver was constructed via IGroupService-only ctor).
                    foreach (var ug in userGroups)
                    {
                        if (ug.GroupId <= 0) continue;
                        List<TreeRedbObject<GroupProps>>? path = null;
                        try
                        {
                            path = await _groupService.GetPathToRootAsync(ug.GroupId, ct).ConfigureAwait(false);
                        }
                        catch (InvalidOperationException)
                        {
                            continue;
                        }

                        foreach (var ancestor in path)
                        {
                            if (ancestor.id == ug.GroupId) continue;
                            if (!string.IsNullOrEmpty(ancestor.name))
                                allGroupNames.Add(ancestor.name);

                            if (inheritedOrg is null
                                && string.Equals(ancestor.Props?.GroupType, "organization", StringComparison.OrdinalIgnoreCase)
                                && !string.IsNullOrEmpty(ancestor.name))
                            {
                                inheritedOrg = ancestor.name;
                            }
                        }
                    }
                }
            }

            foreach (var name in allGroupNames)
            {
                var claim = new Claim(GroupsClaim, name);
                claim.SetDestinations(Destinations.AccessToken, Destinations.IdentityToken);
                identity.AddClaim(claim);
            }

            // RFC-compatible org claim: prefer direct organization-type membership;
            // fall back to closest organization-type ancestor in the tree.
            var directOrg = userGroups.FirstOrDefault(g =>
                string.Equals(g.GroupType, "organization", StringComparison.OrdinalIgnoreCase));
            var orgName = directOrg?.GroupName ?? inheritedOrg;
            if (!string.IsNullOrEmpty(orgName))
            {
                var orgClaim = new Claim(OrgClaim, orgName);
                orgClaim.SetDestinations(Destinations.AccessToken, Destinations.IdentityToken);
                identity.AddClaim(orgClaim);
            }
        }

        if (needRoles)
        {
            // Per-membership role label — NOT inherited via tree (see method remarks).
            var roles = userGroups
                .Where(g => g.Role is not null)
                .Select(g => g.Role!)
                .Distinct()
                .ToList();

            foreach (var role in roles)
            {
                var claim = new Claim(RolesClaim, role);
                claim.SetDestinations(Destinations.AccessToken, Destinations.IdentityToken);
                identity.AddClaim(claim);
            }
        }
    }
}
