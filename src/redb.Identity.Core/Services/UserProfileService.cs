using System.Security.Claims;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Models.Contracts;
using redb.Core.Models.Entities;
using redb.Core.Query;
using redb.Identity.Core.Models;
using redb.Identity.Core.OpenIddict;

namespace redb.Identity.Core.Services;

/// <summary>
/// Default implementation of <see cref="IUserProfileService"/>.
/// Loads Core user + OIDC extension + group memberships in a single call,
/// then builds the ClaimsPrincipal via <see cref="IdentityPrincipalBuilder"/>
/// and enriches with group/role claims via <see cref="GroupClaimsResolver"/>.
/// </summary>
internal sealed class UserProfileService : IUserProfileService
{
    private readonly IRedbService _redb;
    private readonly ILogger<UserProfileService> _logger;

    public UserProfileService(IRedbService redb, ILogger<UserProfileService> logger)
    {
        _redb = redb;
        _logger = logger;
    }

    public async Task<ClaimsPrincipal?> BuildPrincipalAsync(
        long userId,
        IEnumerable<string> scopes,
        bool mfaVerified = false,
        string? mfaMethod = null,
        OidcClaimsRequest? claimsRequest = null,
        CancellationToken ct = default)
    {
        var coreUser = await _redb.UserProvider.GetUserByIdAsync(userId).ConfigureAwait(false);
        if (coreUser is null)
        {
            _logger.LogWarning("UserProfileService: user {UserId} not found", userId);
            return null;
        }

        if (!coreUser.Enabled)
        {
            _logger.LogWarning("UserProfileService: user {UserId} is disabled", userId);
            return null;
        }

        // Load OIDC profile extension (may not exist for users without profile data)
        var oidcObj = await _redb.Query<UserProps>()
            .WhereRedb(o => o.Key == coreUser.Id)
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);

        // The public sub claim is the value_guid on the user's UserProps envelope. If
        // the legacy record has none, lazy-create one and persist so subsequent logins
        // get the same GUID.
        Guid subjectGuid;
        if (oidcObj is null)
        {
            oidcObj = new RedbObject<UserProps>(new UserProps())
            {
                name = coreUser.Login,
                key = coreUser.Id,
                value_guid = Guid.NewGuid()
            };
            await _redb.SaveAsync(oidcObj).ConfigureAwait(false);
            subjectGuid = oidcObj.value_guid!.Value;
        }
        else if (oidcObj.value_guid is null || oidcObj.value_guid == Guid.Empty)
        {
            oidcObj.value_guid = Guid.NewGuid();
            await _redb.SaveAsync(oidcObj).ConfigureAwait(false);
            subjectGuid = oidcObj.value_guid.Value;
        }
        else
        {
            subjectGuid = oidcObj.value_guid.Value;
        }

        var scopeList = scopes as IReadOnlyList<string> ?? scopes.ToList();

        // Build base principal with standard OIDC claims (incl. amr if MFA verified)
        var principal = IdentityPrincipalBuilder.Build(
            coreUser, subjectGuid, oidcObj.Props, scopeList, mfaVerified, mfaMethod, claimsRequest);

        // Enrich with group/role claims
        var resolver = new GroupClaimsResolver(_redb);
        await resolver.EnrichPrincipalAsync(principal, userId, scopeList, ct).ConfigureAwait(false);

        return principal;
    }

    /// <summary>
    /// Fast-path overload: caller (e.g. <c>LoginService.AuthenticateAsync</c>) has already
    /// loaded the Core user, OIDC props, and resolved the subject GUID — skip the redundant
    /// <c>_users</c> + <c>UserProps</c> round-trips. Group memberships are still loaded on
    /// demand when <c>groups</c> / <c>roles</c> scopes are requested.
    /// </summary>
    public async Task<ClaimsPrincipal?> BuildPrincipalAsync(
        IRedbUser user,
        UserProps? oidcProps,
        Guid subjectGuid,
        IEnumerable<string> scopes,
        bool mfaVerified = false,
        string? mfaMethod = null,
        CancellationToken ct = default)
    {
        if (!user.Enabled)
        {
            _logger.LogWarning("UserProfileService: user {UserId} is disabled", user.Id);
            return null;
        }

        var scopeList = scopes as IReadOnlyList<string> ?? scopes.ToList();

        var principal = IdentityPrincipalBuilder.Build(user, subjectGuid, oidcProps, scopeList, mfaVerified, mfaMethod);

        var resolver = new GroupClaimsResolver(_redb);
        await resolver.EnrichPrincipalAsync(principal, user.Id, scopeList, ct).ConfigureAwait(false);

        return principal;
    }
}
