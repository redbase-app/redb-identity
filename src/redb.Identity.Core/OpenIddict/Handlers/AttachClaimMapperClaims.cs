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
/// H5 (v1.0 DoD §5): Applies declarative <see cref="ClaimMapperProps"/> rules to the
/// principal at OpenIddict sign-in time, just before access_token / id_token issuance.
/// <para>
/// Runs uniformly for every grant type (authorization_code, refresh_token, ROPC, device_code,
/// client_credentials), giving Keycloak-equivalent behaviour: global mappers + per-Application
/// overlay + assigned reusable Client Scope mappers, all gated by requested scopes.
/// </para>
/// <para>
/// Order: registered late in the pipeline (after the built-in
/// <c>OpenIddictServerHandlers.Exchange.AttachSignInParameters</c> step but before token
/// minting) so the principal is already populated and we layer mapper-derived claims on top.
/// </para>
/// </summary>
internal sealed class AttachClaimMapperClaims
    : IOpenIddictServerHandler<ProcessSignInContext>
{
    private readonly IServiceProvider _sp;
    private readonly ILogger<AttachClaimMapperClaims> _logger;

    public AttachClaimMapperClaims(IServiceProvider sp, ILogger<AttachClaimMapperClaims> logger)
    {
        _sp = sp;
        _logger = logger;
    }

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        CreateBuilder<ProcessSignInContext>()
            .UseScopedHandler<AttachClaimMapperClaims>()
            // CRITICAL: must run BEFORE OpenIddictServerHandlers.Exchange.ApplyTokenResponse<ProcessSignInContext>
            // (fixed order 500_000), otherwise IsRequestHandled propagates and this handler is silently skipped.
            // Must also run before PrepareAccessTokenPrincipal (AttachAuthorization.Order + 1_000) so any
            // mapper-added claims are visible to the principal-cloning / destination filter logic.
            // Slot: just after AttachAuthorization (which assigns AuthorizationId), before token principal prep.
            .SetOrder(OpenIddictServerHandlers.AttachAuthorization.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ProcessSignInContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Principal?.Identity is not ClaimsIdentity identity)
            return;

        // Resolve internal user id. The public sub is now a GUID; the bigint _users._id
        // rides alongside in the `redb:user_id` claim (end-user grants only). For
        // client_credentials the principal carries no internal user-id claim — skip
        // mappers in that case since they're keyed on user attributes.
        var internalUid = context.Principal.FindFirst(IdentityPrincipalBuilder.InternalUserIdClaim)?.Value;
        if (string.IsNullOrEmpty(internalUid) || !long.TryParse(internalUid, out var userId) || userId <= 0)
            return;

        var redb = _sp.GetService<IRedbService>();
        if (redb is null)
            return; // degraded mode

        // Resolve application object id from client_id, if present
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
                if (app is not null && app.Id > 0)
                    applicationId = app.Id;
            }
            catch (Exception ex)
            {
                // Don't block issuance on app-lookup failure — fall back to global mappers only.
                _logger.LogWarning(ex,
                    "ClaimMappers: failed to resolve application by client_id '{ClientId}'; running global mappers only", clientId);
            }
        }

        // Scopes for this issuance — taken from the principal (already authoritative).
        var scopes = context.Principal.GetScopes();

        var resolverLogger = _sp.GetService<ILogger<ClaimMappersResolver>>();
        var resolver = new ClaimMappersResolver(redb, resolverLogger);

        try
        {
            await resolver.EnrichPrincipalAsync(
                context.Principal, userId, applicationId, scopes, context.CancellationToken)
                .ConfigureAwait(false);
        }
        catch (InvalidOperationException ex)
        {
            // Required-mapper resolution failure — surface as invalid_request to the client.
            _logger.LogWarning(ex,
                "ClaimMappers: required mapper failed for user {UserId}, client {ClientId}", userId, clientId);
            context.Reject(
                error: Errors.InvalidRequest,
                description: "Required claim mapper resolution failed: " + ex.Message);
        }
    }
}
