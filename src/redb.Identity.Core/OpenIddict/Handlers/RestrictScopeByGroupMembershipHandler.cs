using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using redb.Core;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Services;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerDescriptor;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Authorization guard that gates selected OAuth scopes behind group membership.
/// <para>
/// Configured via <see cref="RedbIdentityOptions.ScopeRequiredGroups"/> as a
/// <c>scopeName → groupName</c> map. When a user-bound token request (any grant
/// type that produces a numeric subject — authorization_code, password,
/// device_code, refresh_token derived from the above) requests one of the
/// listed scopes, the request is rejected with <c>error=access_denied</c> unless
/// the authenticated user is a non-expired member of the required group.
/// </para>
/// <para>
/// The <c>client_credentials</c> grant is intentionally excluded: it has no
/// user identity to evaluate, so the existing OpenIddict scope-permission
/// check (<c>scp:{scope}</c> on the application) is the only authoritative
/// gate for that flow.
/// </para>
/// <para>
/// Runs at <see cref="ProcessSignInContext"/> earlier than
/// <see cref="AttachClaimMapperClaims"/> so a denied request never reaches
/// claim-mapper resolution or token minting.
/// </para>
/// </summary>
internal sealed class RestrictScopeByGroupMembershipHandler
    : IOpenIddictServerHandler<ProcessSignInContext>
{
    private readonly IServiceProvider _sp;
    private readonly IOptions<RedbIdentityOptions> _options;
    private readonly ILogger<RestrictScopeByGroupMembershipHandler> _logger;

    public RestrictScopeByGroupMembershipHandler(
        IServiceProvider sp,
        IOptions<RedbIdentityOptions> options,
        ILogger<RestrictScopeByGroupMembershipHandler> logger)
    {
        // NOTE: IOptions<T> (not IOptionsMonitor<T>) is intentional here. Some hosts register
        // identity options via Options.Create(...) as a singleton instance; IOptionsMonitor
        // would build a fresh empty default in that case and silently disable scope gating.
        // ScopeRequiredGroups is read-only after configuration, so no hot-reload is needed.
        _sp = sp;
        _options = options;
        _logger = logger;
    }

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        CreateBuilder<ProcessSignInContext>()
            .UseScopedHandler<RestrictScopeByGroupMembershipHandler>()
            // CRITICAL: must run BEFORE OpenIddictServerHandlers.Exchange.ApplyTokenResponse<ProcessSignInContext>
            // (fixed order 500_000), otherwise IsRequestHandled is propagated and we never execute.
            // We also must run before PrepareAccessTokenPrincipal (AttachAuthorization.Order + 1_000)
            // because rejecting later wastes principal-cloning work. Slot just after AttachDefaultScopes.
            .SetOrder(OpenIddictServerHandlers.AttachDefaultScopes.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ProcessSignInContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var requirements = _options.Value.ScopeRequiredGroups;
        if (requirements is null || requirements.Count == 0)
            return; // feature disabled

        if (context.Principal is null)
            return;

        // The public sub claim is now a GUID; the bigint _users._id rides alongside in
        // the internal `redb:user_id` access-token claim emitted by IdentityPrincipalBuilder.
        // client_credentials tokens carry only a string sub (client_id) and no internal
        // user-id claim → skip (gated scopes for that flow are enforced via scp:* permissions).
        var internalUid = context.Principal.FindFirst(IdentityPrincipalBuilder.InternalUserIdClaim)?.Value;
        if (string.IsNullOrEmpty(internalUid) || !long.TryParse(internalUid, out var userId) || userId <= 0)
            return;

        // Determine which gated scopes are being requested.
        var requestedScopes = context.Principal.GetScopes();
        var gated = new List<KeyValuePair<string, string>>(capacity: 1);
        foreach (var scope in requestedScopes)
        {
            if (requirements.TryGetValue(scope, out var requiredGroup) &&
                !string.IsNullOrWhiteSpace(requiredGroup))
            {
                gated.Add(new KeyValuePair<string, string>(scope, requiredGroup));
            }
        }

        if (gated.Count == 0)
            return; // no gated scopes requested

        var redb = _sp.GetService<IRedbService>();
        if (redb is null)
        {
            // Fail closed: if redb isn't available we cannot verify membership;
            // refusing the gated scope is safer than leaking it.
            _logger.LogError(
                "ScopeAuthorization: IRedbService unavailable; rejecting request for gated scopes {Scopes}",
                string.Join(",", gated.Select(g => g.Key)));
            context.Reject(
                error: Errors.AccessDenied,
                description: "Required group membership cannot be verified.");
            return;
        }

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
            // Fail closed on lookup error.
            _logger.LogError(ex,
                "ScopeAuthorization: GetUserGroupsAsync({UserId}) failed; rejecting gated scopes",
                userId);
            context.Reject(
                error: Errors.AccessDenied,
                description: "Required group membership cannot be verified.");
            return;
        }

        var memberOf = new HashSet<string>(
            userGroups
                .Select(g => g.GroupName)
                .Where(n => !string.IsNullOrEmpty(n))
                .Cast<string>(),
            StringComparer.Ordinal);

        foreach (var (scope, requiredGroup) in gated)
        {
            if (!memberOf.Contains(requiredGroup))
            {
                _logger.LogInformation(
                    "ScopeAuthorization: user {UserId} denied scope '{Scope}' — not a member of group '{Group}'",
                    userId, scope, requiredGroup);
                context.Reject(
                    error: Errors.AccessDenied,
                    description: $"Scope '{scope}' requires membership in group '{requiredGroup}'.");
                return;
            }
        }
    }
}
