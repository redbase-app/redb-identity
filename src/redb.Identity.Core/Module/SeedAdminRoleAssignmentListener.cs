using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using redb.Core;
using redb.Core.Query;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;

namespace redb.Identity.Core.Module;

/// <summary>
/// Bridge the canonical SeedAdmin user (the <c>admin</c> account from the redb SQL
/// seed + <see cref="SeedAdminPasswordHostedService"/>) to the canonical B.3 admin
/// role (the <c>admin</c> system role from <see cref="SeedSystemRolesListener"/>).
///
/// Without this listener the two seeders run in isolation and the admin user
/// never appears in <c>/admin/roles/{adminRoleId}/assignees</c> — operators see
/// the admin role on /admin/roles with zero users next to it and can't tell
/// whether authorisation is actually flowing through the role-based path. The
/// existing <see cref="Routes.Processors.BootstrapAdminProcessor"/> covers a
/// SEPARATE flow (<c>POST /internal/bootstrap-admin</c>) that creates its own
/// admin user + group; installs that never call that endpoint (the common
/// case for the seeded <c>admin</c> account) get the role left empty.
///
/// Runs on every startup AFTER both seeders. Idempotent: looks up the admin
/// user by <see cref="SeedAdminOptions.Login"/>, the admin role by
/// <c>name=admin / audience=organization</c>, and skips when the assignment
/// already exists. Failure is logged at warning level and never blocks
/// startup — the group-scope path remains a safety net.
/// </summary>
internal sealed class SeedAdminRoleAssignmentListener : IRouteLifecycleListener
{
    private readonly IServiceProvider _sp;
    private readonly IOptions<RedbIdentityOptions> _options;

    public SeedAdminRoleAssignmentListener(IServiceProvider sp, IOptions<RedbIdentityOptions> options)
    {
        _sp = sp;
        _options = options;
    }

    public async Task OnContextStarting(IRouteContext context, CancellationToken ct)
    {
        await using var scope = _sp.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var logger = scope.ServiceProvider
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger<SeedAdminRoleAssignmentListener>();

        var seedAdmin = _options.Value.SeedAdmin;
        if (!seedAdmin.Enabled || string.IsNullOrWhiteSpace(seedAdmin.Login))
        {
            logger.LogDebug("SeedAdminRoleAssignmentListener: SeedAdmin disabled or no login configured — skip.");
            return;
        }

        try
        {
            // 1. Resolve admin user by login. Returns null when the SQL seed
            //    hasn't created the row yet (extremely fresh DB) — log + skip;
            //    next startup will catch it.
            var adminUser = await redb.UserProvider.GetUserByLoginAsync(seedAdmin.Login).ConfigureAwait(false);
            if (adminUser is null)
            {
                logger.LogDebug(
                    "SeedAdminRoleAssignmentListener: user with login '{Login}' not found — skip (SQL seed may not have run).",
                    seedAdmin.Login);
                return;
            }

            // 2. Resolve admin role. SeedSystemRolesListener creates it earlier
            //    in the lifecycle chain.
            var adminRole = await redb.Query<RoleProps>()
                .WhereRedb(o => o.Name == "admin")
                .Where(p => p.Audience == "organization")
                .FirstOrDefaultAsync()
                .ConfigureAwait(false);
            if (adminRole is null)
            {
                logger.LogWarning(
                    "SeedAdminRoleAssignmentListener: admin role not seeded — SeedSystemRolesListener must run first.");
                return;
            }

            // 3. Idempotent assign. RoleService.AssignUserAsync no-ops on duplicate.
            var roleSvc = new RoleService(redb);
            var (existingUserIds, _) = await roleSvc.ListAssigneesAsync(adminRole.Id, ct).ConfigureAwait(false);
            if (existingUserIds.Contains(adminUser.Id))
            {
                logger.LogDebug(
                    "SeedAdminRoleAssignmentListener: user {UserId} ({Login}) already in admin role — skip.",
                    adminUser.Id, seedAdmin.Login);
                return;
            }

            await roleSvc.AssignUserAsync(adminRole.Id, adminUser.Id, actingUserId: null, ct).ConfigureAwait(false);
            logger.LogInformation(
                "redb.Identity: seed admin '{Login}' (user id {UserId}) assigned to system admin role (id {RoleId}).",
                seedAdmin.Login, adminUser.Id, adminRole.Id);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "SeedAdminRoleAssignmentListener: failed to mirror seed admin into admin role — UI will show role as empty until next startup.");
        }
    }
}
