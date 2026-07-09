using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using redb.Core;
using redb.Core.Query;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerDescriptor;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// B.3 — emits the <c>roles</c> claim from the first-class Roles registry,
/// independent of any group claim mapper. The emitted set is the user's
/// EFFECTIVE role bundle:
///   direct user assignments (<see cref="UserRoleAssignmentProps"/>)
///   ∪ assignments inherited via every group the user belongs to
///     (<see cref="GroupRoleAssignmentProps"/>).
///
/// Filtered by audience at issuance time:
///   * audience='organization' roles always emit;
///   * audience='application' roles emit only when the role's
///     ApplicationId matches the requesting client's redb object id.
///
/// <para>
/// Runs after <c>AttachClaimMapperClaims</c> + <c>AttachClaimDefinitionEnforcement</c>
/// so the existing per-membership <c>role</c> claim from groups is left
/// intact — the two are complementary: the per-membership label is
/// "what's your role IN this group?", the registry's <c>roles</c> claim is
/// "what access bucket(s) do you hold?". OIDC convention is plural
/// <c>roles</c> (RFC 7643 §4.1.2 / OIDC core §5.1.2); we use that name to
/// match the prior groups+roles emitter behaviour.
/// </para>
/// </summary>
internal sealed class AttachRoleRegistryClaims
    : IOpenIddictServerHandler<ProcessSignInContext>
{
    public const string RolesClaim = "roles";

    private readonly IServiceProvider _sp;
    private readonly ILogger<AttachRoleRegistryClaims> _logger;

    public AttachRoleRegistryClaims(IServiceProvider sp, ILogger<AttachRoleRegistryClaims> logger)
    {
        _sp = sp;
        _logger = logger;
    }

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        CreateBuilder<ProcessSignInContext>()
            .UseScopedHandler<AttachRoleRegistryClaims>()
            // After AttachClaimMapperClaims (+500), after
            // AttachClaimDefinitionEnforcement (+700); before token mint.
            .SetOrder(OpenIddictServerHandlers.AttachAuthorization.Descriptor.Order + 800)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ProcessSignInContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Principal?.Identity is not ClaimsIdentity identity)
            return;

        // client_credentials → no user → no role registry walk.
        var internalUid = context.Principal.FindFirst(IdentityPrincipalBuilder.InternalUserIdClaim)?.Value;
        if (string.IsNullOrEmpty(internalUid) || !long.TryParse(internalUid, out var userId) || userId <= 0)
            return;

        var redb = _sp.GetService<IRedbService>();
        if (redb is null) return;

        // Resolve the requesting application id (for audience='application' filter).
        long? applicationId = null;
        var clientId = context.ClientId;
        if (!string.IsNullOrEmpty(clientId))
        {
            try
            {
                var app = await redb.Query<ApplicationProps>()
                    .WhereRedb(o => o.ValueString == clientId)
                    .FirstOrDefaultAsync()
                    .ConfigureAwait(false);
                if (app is not null && app.Id > 0) applicationId = app.Id;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "AttachRoleRegistryClaims: failed to resolve application by client_id '{ClientId}'; emitting org-scoped roles only", clientId);
            }
        }

        // User's group memberships drive transitive role resolution. IGroupService
        // isn't DI-registered; instantiate GroupService directly against the
        // resolved IRedbService.
        var groupIds = new List<long>();
        try
        {
            var groupService = new GroupService(redb);
            var userGroups = await groupService.GetUserGroupsAsync(userId, context.CancellationToken).ConfigureAwait(false);
            groupIds = userGroups.Where(g => g.GroupId > 0).Select(g => g.GroupId).ToList();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "AttachRoleRegistryClaims: failed to resolve user {UserId} group memberships; emitting direct-role assignments only",
                userId);
        }

        try
        {
            var svc = new RoleService(redb);
            var roles = await svc.GetEffectiveRolesAsync(userId, groupIds, applicationId, context.CancellationToken)
                .ConfigureAwait(false);

            if (roles.Count == 0) return;

            // B.3 (permission picker) — bulk-fetch every effective role's
            // attached scopes and union them into the principal's scope set.
            // OpenIddict's downstream validation still enforces the client's
            // allowed-scope ApplicationProps restriction, so a role can't
            // smuggle in scopes the requesting client isn't authorised for —
            // the union here is purely "if the client COULD ask for X and
            // this user has a role that grants X, give them X without making
            // the operator add X to scope= on every request".
            try
            {
                var attached = await svc.GetEffectiveScopeNamesAsync(roles.Select(r => r.Id), context.CancellationToken)
                    .ConfigureAwait(false);
                if (attached.Count > 0)
                {
                    var existingScopes = context.Principal.GetScopes().ToHashSet(StringComparer.Ordinal);
                    var added = 0;
                    foreach (var s in attached)
                    {
                        if (existingScopes.Add(s)) added++;
                    }
                    if (added > 0)
                    {
                        identity.SetScopes(existingScopes);
                        _logger.LogDebug(
                            "AttachRoleRegistryClaims: added {Count} scope(s) from role attachments for user {UserId} on client {ClientId}",
                            added, userId, clientId);
                    }
                }
            }
            catch (Exception scopeEx)
            {
                _logger.LogWarning(scopeEx,
                    "AttachRoleRegistryClaims: failed to resolve scope attachments for roles of user {UserId}; emitting roles claim without scope augmentation",
                    userId);
            }

            // Idempotent vs prior emitters — drop any already-present `roles`
            // values that the role-registry walk also produces, then re-add
            // the union. Prior emitters (claim mappers, group `roles` scope
            // mapper) are left intact for non-registry sources.
            var existing = identity.FindAll(RolesClaim).Select(c => c.Value).ToHashSet(StringComparer.Ordinal);

            // OpenIddict drops any claim that has no Destinations set, so a
            // raw AddClaim AFTER IdentityPrincipalBuilder has finished its
            // destination switch silently disappears. Set destinations
            // explicitly here — `roles` is conventionally emitted on BOTH
            // tokens (id_token for the front-end, access_token so resource
            // servers don't need a userinfo round-trip).
            string[] destinations = { Destinations.AccessToken, Destinations.IdentityToken };

            foreach (var role in roles)
            {
                var name = role.Props.Name;
                if (string.IsNullOrEmpty(name)) continue;
                if (existing.Contains(name)) continue;
                var claim = new Claim(RolesClaim, name);
                claim.SetDestinations(destinations);
                identity.AddClaim(claim);
                existing.Add(name);
            }
        }
        catch (Exception ex)
        {
            // Failure here must NOT 500 the token endpoint — the principal
            // still has its base claims; the operator just doesn't see the
            // registry-driven roles claim for this issuance.
            _logger.LogError(ex,
                "AttachRoleRegistryClaims: role-registry walk failed for user {UserId}, client {ClientId} — token still issued without registry roles claim",
                userId, clientId);
        }
    }
}
