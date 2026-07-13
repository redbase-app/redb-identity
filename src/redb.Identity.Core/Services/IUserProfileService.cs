using System.Security.Claims;
using redb.Core.Models.Contracts;
using redb.Identity.Core.Models;
using redb.Identity.Core.OpenIddict;

namespace redb.Identity.Core.Services;

/// <summary>
/// Unified user profile and claims service.
/// Single entry point for loading user data (Core + OIDC + groups)
/// and building a ClaimsPrincipal for any grant type or session.
/// </summary>
public interface IUserProfileService
{
    /// <summary>
    /// Builds a <see cref="ClaimsPrincipal"/> for the given user with the specified scopes.
    /// Loads the Core user, OIDC profile extension, and group/role memberships,
    /// then delegates to <see cref="IdentityPrincipalBuilder"/> + <see cref="GroupClaimsResolver"/>.
    /// </summary>
    /// <param name="userId">The <c>_users._id</c> value.</param>
    /// <param name="scopes">Requested OIDC scopes (profile, email, phone, address, groups, roles, etc.).</param>
    /// <param name="mfaVerified">Whether the current session passed MFA. Adds the appropriate <c>amr</c> claim.</param>
    /// <param name="mfaMethod">MFA method id used for verification ("totp", "sms", "email", "webauthn", "recovery").</param>
    /// <param name="claimsRequest">
    /// Parsed <c>claims</c> request parameter (OIDC Core §5.5), when the RP sent one. Only the
    /// authorization endpoint can carry it; every other grant passes null.
    /// </param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Fully populated <see cref="ClaimsPrincipal"/> or null if user not found / disabled.</returns>
    Task<ClaimsPrincipal?> BuildPrincipalAsync(
        long userId,
        IEnumerable<string> scopes,
        bool mfaVerified = false,
        string? mfaMethod = null,
        OidcClaimsRequest? claimsRequest = null,
        CancellationToken ct = default);

    /// <summary>
    /// Fast-path overload for callers that already loaded the Core user + OIDC props +
    /// subject GUID (e.g. <c>LoginService.AuthenticateAsync</c>). Skips the redundant
    /// <c>_users</c> + <c>UserProps</c> round-trips and only loads what isn't supplied —
    /// group memberships when <c>groups</c> / <c>roles</c> scopes are requested.
    /// Behaves identically to the userId-only overload otherwise.
    /// </summary>
    Task<ClaimsPrincipal?> BuildPrincipalAsync(
        IRedbUser user,
        UserProps? oidcProps,
        Guid subjectGuid,
        IEnumerable<string> scopes,
        bool mfaVerified = false,
        string? mfaMethod = null,
        CancellationToken ct = default);
}
