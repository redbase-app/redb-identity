using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Query;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;

namespace redb.Identity.Core.Module;

/// <summary>
/// B.3 backfill — ensure the bootstrap admin user is also a member of the
/// "admin" system role, not just the "admins" group. Bootstrap installs
/// created before the B.3 system-roles listener landed have the admin user
/// in the group (carrying scope <c>identity:admin</c>) but NOT in the role,
/// so role-centric UI surfaces ("Users with this role" on
/// /admin/roles/{id}) misleadingly render "no users".
///
/// This listener walks every group whose name ends in "-admin" or matches
/// the bootstrap admin group (best-effort recovery), finds every member
/// flagged with role="admin", and idempotently assigns each one to the
/// system admin role. Runs every startup after SeedSystemRolesListener
/// (registered in InitRoute right after it), so a fresh bootstrap during
/// the same process boot is also covered.
///
/// Failure is logged at warning level; the group-scope auth path stays
/// functional regardless, so we never block startup.
/// </summary>
internal sealed class BootstrapAdminBackfillListener : IRouteLifecycleListener
{
    private readonly IServiceProvider _sp;

    public BootstrapAdminBackfillListener(IServiceProvider sp) => _sp = sp;

    public async Task OnContextStarting(IRouteContext context, CancellationToken ct)
    {
        await using var scope = _sp.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var logger = scope.ServiceProvider
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger<BootstrapAdminBackfillListener>();

        try
        {
            // 1. Find the system "admin" role.
            var adminRole = await redb.Query<RoleProps>()
                .Where(p => p.Name == "admin")
                .Where(p => p.Audience == "organization")
                .FirstOrDefaultAsync()
                .ConfigureAwait(false);
            if (adminRole is null)
            {
                logger.LogDebug("BootstrapAdminBackfillListener: admin role not seeded yet — skip.");
                return;
            }

            // 2. Find candidate "admins" groups. Bootstrap defaults the name
            //    to "admins"; operators may have renamed it, so we also
            //    sweep any group whose membership row says role=admin.
            var adminGroups = await redb.Query<GroupProps>()
                .WhereRedb(o => o.Name == "admins")
                .ToListAsync()
                .ConfigureAwait(false);
            if (adminGroups.Count == 0)
            {
                logger.LogDebug("BootstrapAdminBackfillListener: no 'admins' group found — bootstrap likely not run yet.");
                return;
            }

            // 3. For every admin group, walk members flagged role=admin,
            //    idempotently assign each to the admin role.
            var groupSvc = scope.ServiceProvider.GetRequiredService<IGroupService>();
            var roleSvc = new RoleService(redb);
            var (existingUserIds, _) = await roleSvc.ListAssigneesAsync(adminRole.Id, ct).ConfigureAwait(false);
            var existingSet = new HashSet<long>(existingUserIds);

            var added = 0;
            foreach (var g in adminGroups)
            {
                var members = await groupSvc.GetMembersAsync(g.Id, ct).ConfigureAwait(false);
                foreach (var m in members)
                {
                    if (m.Role != "admin") continue;
                    if (existingSet.Contains(m.UserId)) continue;
                    try
                    {
                        await roleSvc.AssignUserAsync(adminRole.Id, m.UserId, actingUserId: null, ct).ConfigureAwait(false);
                        existingSet.Add(m.UserId);
                        added++;
                    }
                    catch (Exception ex)
                    {
                        logger.LogWarning(ex,
                            "BootstrapAdminBackfillListener: failed to mirror user {UserId} from group {GroupId} into admin role",
                            m.UserId, g.Id);
                    }
                }
            }

            if (added > 0)
            {
                logger.LogInformation(
                    "redb.Identity: backfilled {Count} admin-group members into the admin role.",
                    added);
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "BootstrapAdminBackfillListener: unexpected failure — group-scope auth remains intact, but role-centric UI may show empty 'admin' role until next restart.");
        }
    }
}
