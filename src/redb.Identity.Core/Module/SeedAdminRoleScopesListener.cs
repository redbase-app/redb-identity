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
/// Give the system <c>admin</c> role the management scope it is named after.
/// <para>
/// <see cref="OpenIddict.Handlers.RestrictAdminScopesByRoleHandler"/> issues an administrative scope
/// only when the user's roles carry it. Before that gate existed nothing ever attached a scope to a
/// role — the console worked because every signed-in account received <c>identity:manage</c> outright —
/// so upgrading an existing installation would find the admin role empty and lock the only
/// administrator out of their own console. This listener closes that gap: on startup, if the system
/// admin role has <b>no</b> scopes attached at all, it attaches the management scope.
/// </para>
/// <para>
/// Deliberately narrow. It fires only when the role's scope list is empty, so an operator who has
/// curated that list — attached three granular scopes, or detached the master one on purpose — is
/// never overruled. It attaches exactly one scope, the master one, because that is what the role
/// already meant in every install that predates the gate; anything finer is the operator's call in
/// Administration → Roles. And it touches only the <c>admin</c> role: <c>everyone</c>,
/// <c>impersonator</c> and <c>system</c> keep whatever they were given.
/// </para>
/// <para>
/// Runs after <see cref="SeedSystemRolesListener"/> (which creates the role) and is idempotent:
/// once the role has a scope, every later startup skips. Failure is logged and never blocks startup —
/// but it is logged at warning level, because a failure here means an administrator may find the
/// console refusing them.
/// </para>
/// </summary>
internal sealed class SeedAdminRoleScopesListener : IRouteLifecycleListener
{
    private const string AdminRoleName = "admin";
    private const string OrganizationAudience = "organization";

    private readonly IServiceProvider _sp;
    private readonly IOptions<RedbIdentityOptions> _options;

    public SeedAdminRoleScopesListener(IServiceProvider sp, IOptions<RedbIdentityOptions> options)
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
            .CreateLogger<SeedAdminRoleScopesListener>();

        var managementScope = _options.Value.ManagementScope;
        if (string.IsNullOrWhiteSpace(managementScope))
        {
            logger.LogWarning("SeedAdminRoleScopesListener: ManagementScope is not configured — skip.");
            return;
        }

        try
        {
            var adminRole = await redb.Query<RoleProps>()
                .WhereRedb(o => o.Name == AdminRoleName)
                .Where(p => p.Audience == OrganizationAudience)
                .FirstOrDefaultAsync()
                .ConfigureAwait(false);
            if (adminRole is null)
            {
                logger.LogWarning(
                    "SeedAdminRoleScopesListener: admin role not seeded — SeedSystemRolesListener must run first.");
                return;
            }

            var roleSvc = new RoleService(redb);
            var attached = await roleSvc.ListScopeIdsForRoleAsync(adminRole.Id, ct).ConfigureAwait(false);
            if (attached.Count > 0)
            {
                logger.LogDebug(
                    "SeedAdminRoleScopesListener: admin role (id {RoleId}) already carries {Count} scope(s) — leaving it alone.",
                    adminRole.Id, attached.Count);
                return;
            }

            // The scope registry holds one object per scope name; V4-UNIQUE keeps ScopeName unique,
            // and value_string carries the same name on rows written before that.
            var scopeObj = await redb.Query<ScopeProps>()
                .WhereRedb(o => o.Name == managementScope)
                .FirstOrDefaultAsync()
                .ConfigureAwait(false)
                ?? await redb.Query<ScopeProps>()
                    .Where(p => p.ScopeName == managementScope)
                    .FirstOrDefaultAsync()
                    .ConfigureAwait(false);
            if (scopeObj is null)
            {
                logger.LogWarning(
                    "SeedAdminRoleScopesListener: scope '{Scope}' is not in the registry — the admin role stays without scopes, "
                    + "and administrators will be refused administrative scopes until it is attached in Administration -> Roles.",
                    managementScope);
                return;
            }

            await roleSvc.AttachScopeAsync(adminRole.Id, scopeObj.Id, actingUserId: null, ct).ConfigureAwait(false);
            logger.LogWarning(
                "redb.Identity: attached '{Scope}' to the system admin role (role id {RoleId}, scope id {ScopeId}). "
                + "Administrative scopes are now issued only to users whose roles carry them; adjust the set in Administration -> Roles.",
                managementScope, adminRole.Id, scopeObj.Id);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "SeedAdminRoleScopesListener: failed to attach '{Scope}' to the admin role — administrators may be refused "
                + "administrative scopes until it is attached manually in Administration -> Roles.",
                managementScope);
        }
    }
}
