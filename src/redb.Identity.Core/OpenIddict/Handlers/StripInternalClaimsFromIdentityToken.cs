using System.Security.Claims;
using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerDescriptor;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Keeps OpenIddict's internal authorization-id reference claim <c>oi_au_id</c> OUT of the
/// issued <c>id_token</c>.
///
/// <para>
/// OpenIddict uses <c>oi_au_id</c> to link a token back to its stored authorization entry. In a
/// JWT (self-contained) configuration it embeds it into the token payload, and because our
/// sign-in principal carries the default <c>[AccessToken, IdentityToken]</c> destinations it
/// leaks into the id_token too. It is a server-internal concern with no meaning to the client,
/// and the OpenID conformance suite flags it as a non-requested id_token claim. We prune the
/// final id_token claim set; the access_token keeps it for introspection linkage.
/// </para>
///
/// <para>
/// NOTE: the sibling claim <c>oi_tkn_id</c> (token id) is INTENTIONALLY left in the id_token —
/// it is the entry identifier OpenIddict needs to revoke the id_token and to drive
/// back-channel logout, both of which this OP supports. It is stamped during id_token
/// generation (not on the principal) and so is not reachable here anyway.
/// </para>
///
/// <para>
/// Runs just before <c>GenerateIdentityToken</c> and edits the already-built
/// <see cref="ProcessSignInContext.IdentityTokenPrincipal"/>. Public OIDC claims (<c>sub</c>,
/// <c>name</c>, …) and our own <c>redb:user_id</c> are untouched (in the id_token by design).
/// </para>
/// </summary>
internal sealed class StripInternalClaimsFromIdentityToken
    : IOpenIddictServerHandler<ProcessSignInContext>
{
    private static readonly string[] InternalClaimTypes = { "oi_au_id" };

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        CreateBuilder<ProcessSignInContext>()
            .UseSingletonHandler<StripInternalClaimsFromIdentityToken>()
            // Just before GenerateIdentityToken serializes context.IdentityTokenPrincipal.
            // OpenIddict copies its internal reference claims (oi_au_id at prepare time,
            // oi_tkn_id later when the token entry is stamped) straight onto the per-token
            // principal, bypassing the destination filter — running last catches both.
            .SetOrder(OpenIddictServerHandlers.GenerateIdentityToken.Descriptor.Order - 1)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ProcessSignInContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.IdentityTokenPrincipal?.Identity is not ClaimsIdentity identity)
            return default;

        foreach (var type in InternalClaimTypes)
        {
            foreach (var claim in identity.FindAll(type).ToList())
                identity.RemoveClaim(claim);
        }

        return default;
    }
}
