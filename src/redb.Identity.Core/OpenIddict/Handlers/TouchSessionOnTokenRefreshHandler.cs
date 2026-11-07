using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using redb.Core;
using redb.Identity.Core.Services;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerDescriptor;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// S-track: bump <c>LastAccessedAt</c> on the session referenced by the
/// principal's <c>sid</c> claim whenever the token endpoint successfully
/// issues new tokens. Covers the refresh_token grant primarily — that's the
/// canonical "this session is still alive" signal in OAuth — and also
/// authorization_code (first issuance) so the row reflects the moment the
/// user actually completed sign-in.
///
/// <para>
/// Fail-closed-ish: any redb / lookup failure is logged + swallowed so a hot
/// path bug never blocks token issuance. The session row will just stay at
/// its previous <c>LastAccessedAt</c> and may get lazy-expired on next list,
/// which is the safe default (slightly more aggressive expiry, never
/// less).
/// </para>
///
/// <para>
/// Pipeline slot: after <see cref="AttachClaimMapperClaims"/> +
/// <see cref="AttachAdditionalIdTokenAudiences"/> so the principal is fully
/// populated, well before token minting so we don't dirty the principal.
/// </para>
/// </summary>
internal sealed class TouchSessionOnTokenRefreshHandler
    : IOpenIddictServerHandler<ProcessSignInContext>
{
    private readonly IServiceProvider _sp;
    private readonly ILogger<TouchSessionOnTokenRefreshHandler> _logger;

    public TouchSessionOnTokenRefreshHandler(
        IServiceProvider sp,
        ILogger<TouchSessionOnTokenRefreshHandler> logger)
    {
        _sp = sp;
        _logger = logger;
    }

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        CreateBuilder<ProcessSignInContext>()
            .UseScopedHandler<TouchSessionOnTokenRefreshHandler>()
            // Just after AttachAdditionalIdTokenAudiences (AttachAuthorization + 501)
            // so the principal is fully resolved. We touch the session
            // regardless of which audience or claim path we took.
            .SetOrder(OpenIddictServerHandlers.AttachAuthorization.Descriptor.Order + 502)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ProcessSignInContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Principal is null) return;

        var sid = context.Principal.GetClaim("sid");
        if (string.IsNullOrEmpty(sid) || !long.TryParse(sid, out var sessionId) || sessionId <= 0)
            return; // no sid → client_credentials or device flow that hasn't established a session

        var activity = context.Request.IsRefreshTokenGrantType() ? "refresh_token"
            : context.Request.IsAuthorizationCodeGrantType() ? "authorization_code"
            : context.Request.IsDeviceCodeGrantType() ? "device_code"
            : context.Request.IsPasswordGrantType() ? "password"
            : "token";

        var redb = _sp.GetService<IRedbService>();
        if (redb is null) return;

        try
        {
            var sessions = new SessionService(redb);
            await sessions.TouchAsync(sessionId, activity, context.CancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Sessions: TouchAsync({SessionId}, {Activity}) failed; session timestamp will lag",
                sessionId, activity);
        }
    }
}
