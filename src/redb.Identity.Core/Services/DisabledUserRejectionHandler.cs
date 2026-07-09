using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Validation;
using redb.Core;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Validation.OpenIddictValidationEvents;

namespace redb.Identity.Core.Services;

/// <summary>
/// Rejects bearer tokens whose subject points to a disabled / soft-deleted user.
/// <para>
/// Standard JWT bearer validation only checks signature + expiry — once a token is
/// issued, deleting or disabling the underlying user account doesn't instantly
/// invalidate the token (the JWT is self-contained, OpenIddict has no per-request
/// hook into the user store). This handler closes that gap: after the built-in
/// principal-extraction handlers have set <c>context.Principal</c>, we load the
/// subject's user row from the redb user store and reject the request if the user
/// is missing or <c>_enabled=false</c> (soft-deleted via <see cref="redb.Core.Providers.Base.UserProviderBase.DeleteUserAsync"/>).
/// </para>
/// <para>
/// Client-credentials tokens (no <c>sub</c> resolvable to a redb user) skip this
/// check — they're scoped to client identity, not a deletable user.
/// </para>
/// </summary>
internal sealed class DisabledUserRejectionHandler
    : IOpenIddictValidationHandler<ProcessAuthenticationContext>
{
    public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
        = OpenIddictValidationHandlerDescriptor
            .CreateBuilder<ProcessAuthenticationContext>()
            // Run AFTER principal-extraction handlers populate context.Principal but
            // before downstream handlers that depend on the principal.
            .UseSingletonHandler<DisabledUserRejectionHandler>()
            .SetOrder(int.MaxValue - 1000)
            .Build();

    private readonly IServiceProvider _sp;
    private readonly ILogger<DisabledUserRejectionHandler> _logger;

    public DisabledUserRejectionHandler(
        IServiceProvider sp,
        ILogger<DisabledUserRejectionHandler> logger)
    {
        _sp = sp;
        _logger = logger;
    }

    public async ValueTask HandleAsync(ProcessAuthenticationContext context)
    {
        if (context.IsRejected) return;
        // For OpenIddict.Validation, the access-token principal lives on
        // `AccessTokenPrincipal` (set by the built-in extraction handlers). The
        // unified `Principal` is set later in the pipeline.
        var principal = context.AccessTokenPrincipal;
        if (principal is null) return;

        // Look for the internal numeric user id — IdentityPrincipalBuilder emits it
        // as `redb:user_id` for end-user grants. CC tokens carry only Claims.Subject
        // (the client id), no redb:user_id → skip them.
        var rawUserId = principal.GetClaim("redb:user_id");
        if (string.IsNullOrEmpty(rawUserId)) return;
        if (!long.TryParse(rawUserId, out var userId) || userId <= 0) return;

        try
        {
            using var scope = _sp.CreateScope();
            var redb = scope.ServiceProvider.GetService<IRedbService>();
            if (redb is null) return;  // misconfigured DI — fail open rather than block all

            var user = await redb.UserProvider.GetUserByIdAsync(userId).ConfigureAwait(false);
            if (user is null || !user.Enabled)
            {
                _logger.LogInformation(
                    "Bearer rejected: user {UserId} is {State}",
                    userId, user is null ? "missing" : "disabled");

                context.Reject(
                    error: Errors.InvalidToken,
                    description: "The user account associated with this token has been disabled or deleted.");
            }
        }
        catch (Exception ex)
        {
            // Don't fail-open on unexpected errors — surface as invalid_token so the
            // caller gets a clear 401 rather than masquerading as a successful auth.
            _logger.LogWarning(ex,
                "Bearer validation failed for user {UserId} — store unavailable", userId);
            context.Reject(
                error: Errors.ServerError,
                description: "Token validation failed due to an internal error.");
        }
    }
}
