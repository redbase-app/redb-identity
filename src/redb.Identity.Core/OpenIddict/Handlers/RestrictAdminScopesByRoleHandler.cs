using System.Collections.Immutable;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using redb.Core;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerDescriptor;
using static OpenIddict.Server.OpenIddictServerHandlers;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// An administrative scope reaches a user-bound token only when that user's roles carry it.
/// <para>
/// OAuth's scope check asks whether the <b>client</b> may request a scope. Nothing in it asks whether
/// the <b>person</b> should have it, and the admin console legitimately requests
/// <c>identity:manage</c> — so before this handler every account that could sign in to the console
/// received the master management scope, and the management API, checking the token as it should,
/// admitted them. Roles were already computed at issuance
/// (<see cref="AttachRoleRegistryClaims"/>) but only ever <i>added</i> scopes; nothing removed one.
/// </para>
/// <para>
/// This handler removes, it never rejects. A user who asked for more than their roles allow still
/// signs in — with the administrative scopes stripped — because refusing the whole request would turn
/// a missing role into a failed login, and the console asks for <c>identity:manage</c> for everyone.
/// Every removal is logged at warning level with the user and the scopes.
/// </para>
/// <para>
/// <c>client_credentials</c> is out of scope by construction: no user, nothing to entitle, and the
/// application's own <c>scp:{scope}</c> permission is the authoritative gate there. Refresh flows run
/// through <see cref="ProcessSignInContext"/> as well, so revoking a role takes effect on the next
/// refresh instead of lingering for the lifetime of the grant.
/// </para>
/// <para>
/// Fail-closed on error: if roles cannot be resolved the administrative scopes are dropped rather than
/// granted on trust. That direction costs an admin a page refresh after a database hiccup; the other
/// direction costs everyone their user list.
/// </para>
/// </summary>
internal sealed class RestrictAdminScopesByRoleHandler
    : IOpenIddictServerHandler<ProcessSignInContext>
{
    private readonly IServiceProvider _sp;
    private readonly IOptions<RedbIdentityOptions> _options;
    private readonly ILogger<RestrictAdminScopesByRoleHandler> _logger;

    public RestrictAdminScopesByRoleHandler(
        IServiceProvider sp,
        IOptions<RedbIdentityOptions> options,
        ILogger<RestrictAdminScopesByRoleHandler> logger)
    {
        // IOptions<T>, not IOptionsMonitor<T>: hosts register identity options as a singleton
        // instance via Options.Create(...), and the monitor would hand back a fresh default —
        // silently disabling the gate. Same reasoning as RestrictScopeByGroupMembershipHandler.
        _sp = sp;
        _options = options;
        _logger = logger;
    }

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        CreateBuilder<ProcessSignInContext>()
            .UseScopedHandler<RestrictAdminScopesByRoleHandler>()
            // One tick after the group gate, which may already have rejected the request, and well
            // before the principal is cloned for token minting.
            .SetOrder(AttachDefaultScopes.Descriptor.Order + 600)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ProcessSignInContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var settings = _options.Value.AdminScopeEntitlement;
        if (settings is null || !settings.Enabled) return;
        if (context.Principal?.Identity is not System.Security.Claims.ClaimsIdentity identity) return;

        // The public sub is a GUID; the internal bigint rides in `redb:user_id`. Its absence means
        // there is no user behind this token (client_credentials) — not this handler's business.
        var internalUid = context.Principal.FindFirst(IdentityPrincipalBuilder.InternalUserIdClaim)?.Value;
        if (string.IsNullOrEmpty(internalUid) || !long.TryParse(internalUid, out var userId) || userId <= 0)
            return;

        var requested = context.Principal.GetScopes();
        var gated = requested.Where(settings.IsGated).ToArray();
        if (gated.Length == 0) return;

        var redb = _sp.GetService<IRedbService>();
        if (redb is null)
        {
            _logger.LogError(
                "AdminScopeEntitlement: IRedbService unavailable; dropping {Scopes} for user {UserId} rather than issuing them unverified",
                string.Join(",", gated), userId);
            Strip(identity, requested, gated);
            return;
        }

        HashSet<string> entitled;
        try
        {
            entitled = await ResolveEntitledScopesAsync(redb, userId, context).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "AdminScopeEntitlement: role resolution failed for user {UserId}; dropping {Scopes}",
                userId, string.Join(",", gated));
            Strip(identity, requested, gated);
            return;
        }

        var refused = gated.Where(s => !entitled.Contains(s)).ToArray();
        if (refused.Length == 0) return;

        _logger.LogWarning(
            "AdminScopeEntitlement: user {UserId} requested {Refused} without a role that grants it; " +
            "issuing the token without those scopes (roles grant: {Entitled})",
            userId, string.Join(",", refused), entitled.Count == 0 ? "<none>" : string.Join(",", entitled));

        Strip(identity, requested, refused);
    }

    /// <summary>Scopes the user's effective roles attach, for the application this token is for.</summary>
    private async Task<HashSet<string>> ResolveEntitledScopesAsync(
        IRedbService redb, long userId, ProcessSignInContext context)
    {
        // Role audience filtering needs the requesting application's redb id: an
        // audience='application' role bound to app A must not entitle a token issued for app B.
        long? applicationId = null;
        var clientId = context.Request?.ClientId;
        if (!string.IsNullOrEmpty(clientId))
        {
            var app = await redb.GetByUniqueAsync<ApplicationProps>(p => p.ClientId, clientId).ConfigureAwait(false);
            if (app is not null && app.Id > 0) applicationId = app.Id;
        }

        // Roles come through groups as well as directly; IGroupService is not DI-registered, so the
        // service is built on the resolved redb exactly as AttachRoleRegistryClaims does it.
        var groupIds = new List<long>();
        var groups = await new GroupService(redb)
            .GetUserGroupsAsync(userId, context.CancellationToken)
            .ConfigureAwait(false);
        groupIds.AddRange(groups.Where(g => g.GroupId > 0).Select(g => g.GroupId));

        var svc = new RoleService(redb);
        var roles = await svc.GetEffectiveRolesAsync(userId, groupIds, applicationId, context.CancellationToken)
            .ConfigureAwait(false);
        if (roles.Count == 0) return new HashSet<string>(StringComparer.Ordinal);

        return await svc.GetEffectiveScopeNamesAsync(roles.Select(r => r.Id), context.CancellationToken)
            .ConfigureAwait(false);
    }

    private static void Strip(
        System.Security.Claims.ClaimsIdentity identity,
        ImmutableArray<string> requested,
        IReadOnlyCollection<string> refused)
    {
        var keep = requested.Where(s => !refused.Contains(s, StringComparer.Ordinal)).ToArray();
        identity.SetScopes(keep);
    }
}
