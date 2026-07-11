using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Server;
using redb.Identity.Core.OpenIddict.Handlers;
using redb.Identity.Core.Services;

namespace redb.Identity.Core.OpenIddict;

/// <summary>
/// Extension methods for configuring the redb.Route OpenIddict Server host adapter.
/// </summary>
public static class RedbRouteOpenIddictServerBuilderExtensions
{
    /// <summary>
    /// All handler descriptors registered by the redb.Route adapter.
    /// </summary>
    internal static readonly OpenIddictServerHandlerDescriptor[] HandlerDescriptors =
    [
        // Extract handlers
        ExtractTokenRequestHandler.Descriptor,
        ExtractAuthorizationRequestHandler.Descriptor,
        ExtractUserinfoRequestHandler.Descriptor,
        ExtractIntrospectionRequestHandler.Descriptor,
        ExtractRevocationRequestHandler.Descriptor,
        ExtractDeviceRequestHandler.Descriptor,
        ExtractVerificationRequestHandler.Descriptor,
        ExtractConfigurationRequestHandler.Descriptor,
        ExtractJwksRequestHandler.Descriptor,
        ExtractPushedAuthorizationRequestHandler.Descriptor,

        // Client credentials from Authorization header (Basic auth)
        ExtractClientCredentialsHandler.Descriptor,
        ExtractIntrospectionClientCredentialsHandler.Descriptor,
        ExtractRevocationClientCredentialsHandler.Descriptor,

        // Apply handlers
        ApplyTokenResponseHandler.Descriptor,
        ApplyAuthorizationResponseHandler.Descriptor,
        ApplyUserinfoResponseHandler.Descriptor,
        ApplyIntrospectionResponseHandler.Descriptor,
        // RFC 7662 §2.2 — surface the internal bigint user id (redb:user_id)
        // on introspection responses for user-grant tokens. Runs immediately
        // BEFORE the response writer above so the field is in
        // context.Response before serialisation.
        AttachInternalUserIdToIntrospectionResponse.Descriptor,
        ApplyRevocationResponseHandler.Descriptor,
        ApplyDeviceResponseHandler.Descriptor,
        ApplyVerificationResponseHandler.Descriptor,
        ApplyDiscoveryResponseHandler.Descriptor,
        ApplyJwksResponseHandler.Descriptor,
        ApplyPushedAuthorizationResponseHandler.Descriptor,

        // Handle (business logic) handlers
        HandleTokenRequestHandler.Descriptor,
        AttachSessionPrincipalHandler.Descriptor,
        HandleAuthorizationRequestHandler.Descriptor,
        HandleVerificationRequestHandler.Descriptor,

        // Userinfo: supplement built-in AttachClaims with additional OIDC standard claims
        AttachAdditionalUserinfoClaims.Descriptor,

        // Group-membership scope authorization (gates scopes like 'identity:manage'
        // behind admin group membership). Runs earlier than AttachClaimMapperClaims
        // so a denied request never triggers mapper resolution.
        RestrictScopeByGroupMembershipHandler.Descriptor,

        // β: per-application group whitelist (ApplicationProps.AllowedGroups).
        // Runs one tick after the scope gate so denied-by-scope requests carry
        // the more specific scope error rather than the generic app error.
        RestrictApplicationByGroupMembershipHandler.Descriptor,

        // H5 (DoD §5): apply declarative claim mappers (global + per-app + Client-Scope) at sign-in
        AttachClaimMapperClaims.Descriptor,

        // S2.4: per-app ClaimDefinitionProps enforcement (required-claim gate at
        // token issuance) + per-definition EmitOnIdToken/AccessToken destinations.
        // Runs AFTER claim mappers so mapper-added claims also get destinations
        // rewritten when they match a definition name.
        AttachClaimDefinitionEnforcement.Descriptor,

        // B.3: Roles registry → `roles` claim. Effective role set = direct user
        // assignments ∪ transitive assignments via groups, filtered by audience.
        // Runs AFTER claim mappers (+500) AND definition enforcement (+700) so
        // the registry is the LAST word on the `roles` claim.
        AttachRoleRegistryClaims.Descriptor,

        // A.3: append extra audiences from ApplicationProps.IdTokenAudiences to the
        // sign-in principal so the issued id_token's aud claim covers federated
        // downstream resource servers in addition to the implicit client_id default.
        AttachAdditionalIdTokenAudiences.Descriptor,

        // Strip OpenIddict's internal oi_au_id (authorization id) reference claim from the
        // id_token (leaks in a JWT config; kept on the access_token). oi_tkn_id is left in
        // by design — it drives id_token revocation / back-channel logout. OIDC hygiene.
        StripInternalClaimsFromIdentityToken.Descriptor,

        // S-track: bump SessionProps.LastAccessedAt on the session carried by
        // the principal whenever the token endpoint mints new tokens — proves
        // the session is still alive, drives idle-timeout calculation.
        TouchSessionOnTokenRefreshHandler.Descriptor,

        // Z4 (RFC 9449): DPoP proof validation + cnf.jkt binding
        ValidateDpopProofHandler.Descriptor,
        AttachDpopConfirmationClaimHandler.Descriptor,

        // Z4 P2 (RFC 9449 \u00a710): dpop_jkt binding on /authorize \u2194 enforcement at /token
        BindDpopJktAtAuthorizeHandler.Descriptor,
        EnforceDpopJktBindingHandler.Descriptor,
    ];

    /// <summary>
    /// Registers the redb.Route host adapter for the OpenIddict Server pipeline.
    /// This enables processing OAuth/OIDC requests through <see cref="IExchange"/>
    /// instead of ASP.NET Core or OWIN.
    /// </summary>
    /// <param name="builder">The OpenIddict Server builder.</param>
    /// <returns>A <see cref="RedbRouteOpenIddictServerBuilder"/> for further configuration.</returns>
    public static RedbRouteOpenIddictServerBuilder UseRedbRoute(
        this OpenIddictServerBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        // Register the entry-point handler that routes use to drive the pipeline
        builder.Services.TryAddSingleton<RedbRouteOpenIddictServerHandler>();

        // Register handler services in DI (required for dispatcher resolution)
        foreach (var descriptor in HandlerDescriptors)
        {
            builder.Services.TryAdd(descriptor.ServiceDescriptor);
        }

        // Z4 (RFC 9449): the DPoP handlers above are registered unconditionally,
        // so their dependencies must always resolve from DI. Provide safe defaults
        // (Memory replay-store) here; full configuration override lives in
        // RedbIdentityServiceExtensions when DPoP is enabled.
        builder.Services.TryAddSingleton<IDpopReplayStore>(sp =>
            new MemoryDpopReplayStore(sp.GetService<TimeProvider>(), null));
        builder.Services.TryAddSingleton<DpopProofValidator>();
        // Z4 P2 (RFC 9449 §8): default stateless HMAC nonce provider. Override with
        // a Redis/redb-backed instance for shared validity across cluster nodes.
        builder.Services.TryAddSingleton<IDpopNonceProvider, HmacDpopNonceProvider>();

        // Register the PostConfigure that adds handler descriptors to options.Handlers
        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IPostConfigureOptions<OpenIddictServerOptions>,
                RedbRouteOpenIddictServerConfiguration>());

        return new RedbRouteOpenIddictServerBuilder(builder);
    }
}
