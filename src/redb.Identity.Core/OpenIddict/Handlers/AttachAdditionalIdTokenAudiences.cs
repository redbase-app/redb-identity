using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using redb.Core;
using redb.Core.Query;
using redb.Identity.Core.Models;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerDescriptor;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// A.3: Appends extra <c>aud</c> claims (destination <see cref="Destinations.IdentityToken"/>)
/// onto the sign-in principal so the issued <c>id_token</c> can be consumed by federated
/// downstream resource servers in addition to the issuing client.
///
/// <para>
/// Per OIDC core §2 the default audience of an id_token is the client_id of the requesting
/// client; OpenIddict sets this via its built-in
/// <see cref="OpenIddictServerHandlers.Exchange.AttachIdentityTokenPrincipal"/>. This
/// handler is a strict superset operation — never replaces or removes the default — that
/// reads each entry of <see cref="ApplicationProps.IdTokenAudiences"/> and adds it as an
/// additional <c>aud</c> claim restricted to the IdentityToken destination (it MUST NOT
/// leak onto the access_token, whose audiences belong to the resource server and not the
/// id_token consumer set).
/// </para>
///
/// <para>
/// Pipeline order: registered alongside <see cref="AttachClaimMapperClaims"/> on
/// <see cref="ProcessSignInContext"/>, just after AttachAuthorization (which assigns the
/// AuthorizationId) so the principal is already populated, and well before
/// PrepareIdentityTokenPrincipal so the destinations propagate correctly.
/// </para>
///
/// <para>
/// Failure modes are deliberately silent: a redb-lookup failure, a missing client_id, or
/// a degraded service-provider state all short-circuit cleanly — token issuance continues
/// with the default client_id-only audience. The handler never blocks sign-in.
/// </para>
/// </summary>
internal sealed class AttachAdditionalIdTokenAudiences
    : IOpenIddictServerHandler<ProcessSignInContext>
{
    private readonly IServiceProvider _sp;
    private readonly ILogger<AttachAdditionalIdTokenAudiences> _logger;

    public AttachAdditionalIdTokenAudiences(
        IServiceProvider sp,
        ILogger<AttachAdditionalIdTokenAudiences> logger)
    {
        _sp = sp;
        _logger = logger;
    }

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        CreateBuilder<ProcessSignInContext>()
            .UseScopedHandler<AttachAdditionalIdTokenAudiences>()
            // Same slot as AttachClaimMapperClaims — runs after AttachAuthorization
            // (which seeds the AuthorizationId) and before the principal clones that
            // build the per-token principals. Picking +501 puts us deterministically
            // after the claim-mapper pass, so any mapper-derived audience claims (if
            // a future mapper ever emits one) win and we layer on top.
            .SetOrder(OpenIddictServerHandlers.AttachAuthorization.Descriptor.Order + 501)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ProcessSignInContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Principal?.Identity is not ClaimsIdentity identity)
            return;

        var clientId = context.ClientId;
        if (string.IsNullOrEmpty(clientId))
            return;

        var redb = _sp.GetService<IRedbService>();
        if (redb is null)
            return; // degraded — proceed without extra audiences.

        ApplicationProps? props = null;
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
            _logger.LogWarning(ex,
                "IdTokenAudiences: failed to resolve application by client_id '{ClientId}'; skipping extra audiences", clientId);
            return;
        }

        var extras = props?.IdTokenAudiences;
        if (extras is null || extras.Length == 0)
            return;

        // De-dupe against the client_id default and any audiences a previous handler
        // (e.g. a future claim-mapper) already attached. Reading
        // identity.FindAll(Claims.Audience) is cheap — usually 1-2 entries.
        var existing = new HashSet<string>(
            identity.FindAll(Claims.Audience).Select(c => c.Value),
            StringComparer.Ordinal);
        existing.Add(clientId); // belt-and-braces: client_id is the implicit default.

        foreach (var aud in extras)
        {
            if (string.IsNullOrWhiteSpace(aud)) continue;
            if (!existing.Add(aud)) continue;

            var claim = new Claim(Claims.Audience, aud);
            // Restrict to IdentityToken — access_token audiences are a separate
            // concept (resource indicators / RFC 8707) that we'd compose elsewhere.
            claim.SetDestinations(Destinations.IdentityToken);
            identity.AddClaim(claim);
        }
    }
}
