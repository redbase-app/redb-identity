using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using redb.Core;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerDescriptor;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// RFC 9068 §2.2/§3: composes the resource indicators of the sign-in principal, which
/// OpenIddict's <c>PrepareAccessTokenPrincipal</c> turns into the access token's <c>aud</c>.
///
/// <para>
/// The set is the union of the granted scopes' <c>Resources</c> (the OpenIddict-canonical
/// scope → resource mapping served by the scope store) and the application's
/// <c>AccessTokenAudiences</c>. The OP's own audience
/// (<see cref="RedbIdentityOptions.DefaultAccessTokenAudience"/>) joins whenever an
/// <c>identity:*</c> scope is granted — those scopes ARE the OP's own API — and stands
/// alone as the §3 default resource indicator when nothing else names a resource. A token
/// minted for an external API only therefore never carries the OP's audience, and the
/// local validation stack rejects it at the management API (§4).
/// </para>
///
/// <para>
/// Fail-closed on lookup failures: an exception from the scope store or the application
/// lookup propagates and the token is not issued — an access token with a wrong audience is a
/// security defect. Absent infrastructure is a different matter: OpenIddict's degraded mode
/// (no core, no stores — the unit-test and embedded configurations) has no scope manager and
/// no application store, so there is nothing to look up and only the OP's own audience applies.
/// </para>
/// </summary>
internal sealed class AttachAccessTokenResources : IOpenIddictServerHandler<ProcessSignInContext>
{
    /// <summary>Scopes with this prefix belong to the OP's own API surface.</summary>
    internal const string OwnScopePrefix = "identity:";

    private readonly IServiceProvider _sp;

    public AttachAccessTokenResources(IServiceProvider sp) => _sp = sp;

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        CreateBuilder<ProcessSignInContext>()
            .UseScopedHandler<AttachAccessTokenResources>()
            // Same slot family as AttachAdditionalIdTokenAudiences (+501) and
            // TouchSessionOnTokenRefresh (+502): after AttachAuthorization, before the
            // per-token principal clones read the resources.
            .SetOrder(OpenIddictServerHandlers.AttachAuthorization.Descriptor.Order + 503)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ProcessSignInContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Principal is null)
            return;

        // The OP's issuer as OpenIddict sees it (SetIssuer(options.Issuer) in production, so the
        // validation side computes the same value from options); the options value is the fallback.
        var options = _sp.GetRequiredService<IOptions<RedbIdentityOptions>>().Value;
        var ownAudience = RedbIdentityOptions.ResolveDefaultAccessTokenAudience(
            context.Options.Issuer ?? options.Issuer, options.DefaultAccessTokenAudience);

        var scopes = context.Principal.GetScopes();
        var resources = new HashSet<string>(StringComparer.Ordinal);

        var scopeManager = _sp.GetService<IOpenIddictScopeManager>();
        if (scopeManager is not null)
        {
            await foreach (var resource in scopeManager
                .ListResourcesAsync(scopes, context.CancellationToken)
                .ConfigureAwait(false))
            {
                if (!string.IsNullOrWhiteSpace(resource))
                    resources.Add(resource);
            }
        }

        var redb = _sp.GetService<IRedbService>();
        if (redb is not null && !string.IsNullOrEmpty(context.ClientId))
        {
            var app = await redb.GetByUniqueAsync<ApplicationProps>(p => p.ClientId, context.ClientId)
                .ConfigureAwait(false);
            foreach (var audience in app?.Props.AccessTokenAudiences ?? [])
            {
                if (!string.IsNullOrWhiteSpace(audience))
                    resources.Add(audience);
            }
        }

        if (scopes.Any(s => s.StartsWith(OwnScopePrefix, StringComparison.Ordinal)))
            resources.Add(ownAudience);

        if (resources.Count == 0)
            resources.Add(ownAudience);

        // The requesting client is an audience of its own token as well (WSO2 default, Keycloak,
        // Entra for self-scoped tokens). Without it the issuing client could no longer introspect
        // the tokens it holds: once a token carries audiences, OpenIddict admits only audience
        // members to /connect/introspect (ID2077) and no longer falls back to the presenter.
        // Added after the default so "nothing configured → {issuer}/resources" still holds.
        if (!string.IsNullOrEmpty(context.ClientId))
            resources.Add(context.ClientId);

        context.Principal.SetResources(resources);
    }
}
