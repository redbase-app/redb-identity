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
/// β: per-application whitelist gate. When
/// <see cref="ApplicationProps.AllowedGroups"/> is non-empty, only users who
/// are a member of at least one listed group may authenticate against this
/// application. Rejects with <c>access_denied</c> otherwise.
///
/// <para>
/// Independent of and OR'd against
/// <see cref="RestrictScopeByGroupMembershipHandler"/> (which gates per-scope
/// rather than per-application). Both gates must pass — denying either
/// short-circuits the sign-in.
/// </para>
///
/// <para>
/// Pipeline order: same slot as the scope gate
/// (AttachDefaultScopes.Order + 501) so we run just after the per-scope
/// check and reject before any expensive principal-cloning happens.
/// </para>
///
/// <para>
/// Skipped grants:
///   - <c>client_credentials</c> — there's no end-user principal to verify,
///     and the application's own permission to mint a token rides on its
///     existing scp:* / gt:client_credentials permissions, not on user
///     group membership.
///   - Anonymous / no-client_id requests — handled by the standard
///     OpenIddict validators upstream.
/// </para>
///
/// <para>
/// Fail-closed semantics on redb / lookup failure: if we can't determine
/// the user's group membership, we reject. Leaking access on infrastructure
/// failure is the wrong default.
/// </para>
/// </summary>
internal sealed class RestrictApplicationByGroupMembershipHandler
    : IOpenIddictServerHandler<ProcessSignInContext>
{
    private readonly IServiceProvider _sp;
    private readonly ILogger<RestrictApplicationByGroupMembershipHandler> _logger;

    public RestrictApplicationByGroupMembershipHandler(
        IServiceProvider sp,
        ILogger<RestrictApplicationByGroupMembershipHandler> logger)
    {
        _sp = sp;
        _logger = logger;
    }

    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = CreateBuilder<ProcessSignInContext>()
            .UseScopedHandler<RestrictApplicationByGroupMembershipHandler>()
            // Run one tick after the per-scope gate so a denied-by-scope request
            // never reaches us (and the audit log carries the more specific error).
            .SetOrder(OpenIddictServerHandlers.AttachDefaultScopes.Descriptor.Order + 501)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ProcessSignInContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Principal is null) return;

        var clientId = context.ClientId;
        if (string.IsNullOrEmpty(clientId)) return;

        // Skip client_credentials — no end-user principal to evaluate. The
        // application's own permission to mint a token already gated upstream
        // via scp:* / gt:client_credentials.
        var internalUid = context.Principal.FindFirst(IdentityPrincipalBuilder.InternalUserIdClaim)?.Value;
        if (string.IsNullOrEmpty(internalUid) || !long.TryParse(internalUid, out var userId) || userId <= 0)
            return;

        var redb = _sp.GetService<IRedbService>();
        if (redb is null)
        {
            _logger.LogError(
                "AppAuthorization: IRedbService unavailable; rejecting client_id='{ClientId}'", clientId);
            context.Reject(
                error: Errors.AccessDenied,
                description: "Application membership cannot be verified.");
            return;
        }

        // Resolve application by client_id.
        ApplicationProps? props;
        try
        {
            var app = await redb.Query<ApplicationProps>()
                .WhereRedb(o => o.ValueString == clientId)
                .FirstOrDefaultAsync()
                .ConfigureAwait(false);
            props = app?.Hydrate().Props;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "AppAuthorization: failed to resolve application by client_id '{ClientId}'", clientId);
            context.Reject(
                error: Errors.AccessDenied,
                description: "Application membership cannot be verified.");
            return;
        }

        if (props is null)
            return; // unknown client — let downstream validators 404 it

        var allowed = props.AllowedGroups;
        if (allowed is null || allowed.Length == 0)
            return; // no whitelist — feature disabled for this app

        var allowedSet = new HashSet<string>(allowed, StringComparer.Ordinal);

        IGroupService groupService = new GroupService(redb);
        List<IGroupService.UserGroupInfo> userGroups;
        try
        {
            userGroups = await groupService
                .GetUserGroupsAsync(userId, context.CancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "AppAuthorization: GetUserGroupsAsync({UserId}) failed for client_id='{ClientId}'",
                userId, clientId);
            context.Reject(
                error: Errors.AccessDenied,
                description: "Application membership cannot be verified.");
            return;
        }

        var memberOf = userGroups
            .Select(g => g.GroupName)
            .Where(n => !string.IsNullOrEmpty(n));

        foreach (var groupName in memberOf)
        {
            if (allowedSet.Contains(groupName!))
                return; // user is in at least one allowed group — accept
        }

        _logger.LogInformation(
            "AppAuthorization: user {UserId} denied access to '{ClientId}' — not a member of any allowed group [{Groups}]",
            userId, clientId, string.Join(",", allowed));

        context.Reject(
            error: Errors.AccessDenied,
            description: $"This application restricts access to specific groups; the user is not a member of any of them.");
    }
}
