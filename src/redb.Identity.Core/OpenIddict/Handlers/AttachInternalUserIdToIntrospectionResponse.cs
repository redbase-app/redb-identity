using OpenIddict.Server;
using redb.Identity.Core.Services;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Surfaces the internal bigint user id (<see cref="IdentityPrincipalBuilder.InternalUserIdClaim"/>
/// = <c>redb:user_id</c>) on the RFC 7662 introspection response when the
/// introspected token belongs to a user grant (ROPC / authorization_code /
/// refresh / device_code).
///
/// <para>
/// RFC 7662 §2.2 explicitly authorises implementation-defined top-level
/// response members alongside the standard set. <c>redb:user_id</c> follows
/// RFC 7519 §4.3 private-claim naming (colon-prefixed vendor namespace) so it
/// won't collide with future IANA-registered names.
/// </para>
///
/// <para>
/// Client-credentials tokens have no user — they're never enriched here.
/// The claim is on the principal already (see
/// <see cref="IdentityPrincipalBuilder"/>); OpenIddict's default
/// introspection serializer only emits the standard whitelist, so this
/// handler forwards the value into <c>context.Response</c> just before the
/// builder-level <see cref="ApplyIntrospectionResponseHandler"/> writes the
/// response to the route exchange.
/// </para>
/// </summary>
internal sealed class AttachInternalUserIdToIntrospectionResponse
    : IOpenIddictServerHandler<HandleIntrospectionRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleIntrospectionRequestContext>()
            .UseSingletonHandler<AttachInternalUserIdToIntrospectionResponse>()
            // Late in the handle stage — AFTER OpenIddict's standard claim-
            // projection handlers have populated context.Response with
            // sub/jti/iat/etc.; the surrounding Apply* writer descriptors
            // serialise the dictionary into the HTTP body.
            .SetOrder(int.MaxValue - 1000)
            .Build();

    public ValueTask HandleAsync(HandleIntrospectionRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        // Rejected / active=false paths skip Principal entirely.
        var principal = context.Principal;
        if (principal is null) return default;

        var uid = principal.FindFirst(IdentityPrincipalBuilder.InternalUserIdClaim)?.Value;
        if (string.IsNullOrEmpty(uid)) return default;

        // OpenIddict's HandleIntrospectionRequestContext.Claims is the
        // dictionary the Apply* writer flattens into the JSON response
        // alongside the standard RFC 7662 fields. Idempotent — leave any
        // pre-existing value alone.
        if (context.Claims.ContainsKey(IdentityPrincipalBuilder.InternalUserIdClaim))
            return default;

        context.Claims[IdentityPrincipalBuilder.InternalUserIdClaim] = uid;
        return default;
    }
}
