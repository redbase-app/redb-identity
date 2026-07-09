using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;

namespace redb.Identity.Core.Module;

/// <summary>
/// B.3 — seed the four canonical built-in roles (system / everyone / admin /
/// impersonator) on every Identity startup. Idempotent: skips any role that
/// already exists by name + audience. Operators can rename DisplayName or
/// Description through the admin API, but the API blocks delete on
/// IsSystem=true (RoleService.DeleteRoleAsync), so the seed stays
/// authoritative for the "what roles ship with Identity" answer.
/// </summary>
internal sealed class SeedSystemRolesListener : IRouteLifecycleListener
{
    private readonly IServiceProvider _sp;

    public SeedSystemRolesListener(IServiceProvider sp) => _sp = sp;

    public async Task OnContextStarting(IRouteContext context, CancellationToken ct)
    {
        await using var scope = _sp.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var logger = scope.ServiceProvider
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger<SeedSystemRolesListener>();

        var svc = new RoleService(redb);

        var defaults = new (string Name, string DisplayName, string Description)[]
        {
            ("system",       "System",       "Process-level identity used by background jobs and bootstrap. Never assigned to end users."),
            ("everyone",     "Everyone",     "Implicit role every authenticated user holds. Used as a default audience for org-wide claim emission."),
            ("admin",        "Administrator", "Full administrative access to the Identity surface — manage users, applications, scopes, claim definitions, roles."),
            ("impersonator", "Impersonator", "Holders can mint act-as tokens for other users via the impersonation flow. Audit-tracked."),
        };

        var created = 0;
        var skipped = 0;
        foreach (var (name, displayName, description) in defaults)
        {
            try
            {
                var existing = await redb.Query<RoleProps>()
                    .Where(p => p.Name == name)
                    .Where(p => p.Audience == "organization")
                    .FirstOrDefaultAsync()
                    .ConfigureAwait(false);
                if (existing is not null)
                {
                    skipped++;
                    continue;
                }

                await svc.CreateRoleAsync(
                    name, "organization", applicationId: null,
                    displayName: displayName,
                    description: description,
                    isSystem: true,
                    ct).ConfigureAwait(false);
                created++;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex,
                    "SeedSystemRolesListener: failed to seed system role '{Name}' — operator can recreate via admin API",
                    name);
            }
        }

        logger.LogInformation(
            "redb.Identity: system roles seed complete (created={Created} skipped={Skipped})",
            created, skipped);
    }
}
