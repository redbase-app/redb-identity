using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Core.Query;
using redb.Identity.Contracts.Configuration;
using redb.Identity.Core.Models;
using redb.Route.Abstractions;

namespace redb.Identity.Core.Module;

/// <summary>
/// Seed the static <see cref="IdentityScopes"/> catalogue into the
/// <c>identity.scope</c> store on every startup. Without this the role-
/// permission picker on <c>/admin/roles/{id}</c> can only attach scopes
/// that some demo or operator explicitly created via the admin API.
/// Idempotent: skips any scope already present by exact name match on
/// <c>_objects.value_string</c>.
///
/// Descriptions read like operator-facing UI labels because the picker
/// surfaces them verbatim. Order in the seed array dictates picker
/// ordering within a resource group.
/// </summary>
internal sealed class SeedSystemScopesListener : IRouteLifecycleListener
{
    private readonly IServiceProvider _sp;

    public SeedSystemScopesListener(IServiceProvider sp) => _sp = sp;

    public async Task OnContextStarting(IRouteContext context, CancellationToken ct)
    {
        await using var scope = _sp.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var logger = scope.ServiceProvider
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger<SeedSystemScopesListener>();

        var defaults = new (string Name, string Description)[]
        {
            // Universal
            (IdentityScopes.Manage,
                "Full administrative access — implies every granular scope below."),
            (IdentityScopes.Account,
                "Self-service — token may target only the owning user's /me endpoints."),
            (IdentityScopes.ReadOnly,
                "Read-only admin — GET on any management endpoint, mutations rejected."),

            // Users surface
            (IdentityScopes.UsersRead,           "Read users and group memberships."),
            (IdentityScopes.UsersWrite,          "Create, update, delete users; manage group memberships."),

            (IdentityScopes.GroupsRead,          "Read groups and their hierarchy."),
            (IdentityScopes.GroupsWrite,         "Create, update, delete groups and members."),

            (IdentityScopes.ConsentsRead,        "Read users' OAuth consents."),
            (IdentityScopes.ConsentsWrite,       "Revoke users' OAuth consents on their behalf."),

            (IdentityScopes.MfaRead,             "Read users' MFA enrolment status."),
            (IdentityScopes.MfaWrite,            "Reset, replace, disable users' MFA enrolments."),

            // Application / OIDC config surface
            (IdentityScopes.ApplicationsRead,    "Read OAuth/OIDC applications and clients."),
            (IdentityScopes.ApplicationsWrite,   "Create, update, delete applications; rotate client secrets."),

            (IdentityScopes.ScopesRead,          "Read OAuth scope definitions."),
            (IdentityScopes.ScopesWrite,         "Create, update, delete OAuth scopes."),

            (IdentityScopes.RolesRead,           "Read roles, assignees, and attached scopes."),
            (IdentityScopes.RolesWrite,          "Create, update, delete roles; assign users/groups; attach scopes."),

            (IdentityScopes.ClaimsRead,          "Read claim mappers, definitions, and scope assignments."),
            (IdentityScopes.ClaimsWrite,         "Create, update, delete claim mappers, definitions, and scope assignments."),

            (IdentityScopes.FederationRead,      "Read external identity providers (Google, Microsoft, OIDC, SAML)."),
            (IdentityScopes.FederationWrite,     "Create, update, delete external identity provider configurations."),

            (IdentityScopes.WebhooksRead,        "Read outbound webhook subscriptions."),
            (IdentityScopes.WebhooksWrite,       "Create, update, delete webhook subscriptions; rotate HMAC secrets."),

            (IdentityScopes.SigningKeysRead,     "Read the JWKS catalogue and key metadata."),
            (IdentityScopes.SigningKeysWrite,    "Rotate, retire, deactivate signing keys."),

            // Runtime surface
            (IdentityScopes.SessionsRead,        "Read user sessions across all subjects."),
            (IdentityScopes.SessionsWrite,       "Revoke sessions and manage the revoked-sid blacklist."),

            (IdentityScopes.TokensRead,          "Read issued OAuth tokens (admin browse)."),
            (IdentityScopes.TokensWrite,         "Revoke and prune issued OAuth tokens."),

            (IdentityScopes.AuditRead,           "Read the immutable identity audit log."),

            (IdentityScopes.Impersonate,         "Mint impersonate-as tokens (RFC 8693 token exchange with act claim)."),
        };

        var created = 0;
        var skipped = 0;
        foreach (var (name, description) in defaults)
        {
            try
            {
                var existing = await redb.Query<ScopeProps>()
                    .WhereRedb(o => o.ValueString == name)
                    .FirstOrDefaultAsync()
                    .ConfigureAwait(false);
                if (existing is not null)
                {
                    skipped++;
                    continue;
                }

                var obj = new RedbObject<ScopeProps>(new ScopeProps
                {
                    ScopeName = name,
                    Description = description,
                });
                obj.Name = name;
                obj.value_string = name;
                await redb.SaveAsync(obj).ConfigureAwait(false);
                created++;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex,
                    "SeedSystemScopesListener: failed to seed system scope '{Name}' — picker UX will be missing it.",
                    name);
            }
        }

        logger.LogInformation(
            "redb.Identity: system scopes seed complete (created={Created} skipped={Skipped})",
            created, skipped);
    }
}
