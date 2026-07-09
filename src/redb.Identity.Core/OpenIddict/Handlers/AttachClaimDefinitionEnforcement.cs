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
/// S2.4 — apply <see cref="ClaimDefinitionProps"/> at token issuance:
/// <list type="number">
///   <item>Per-application required-claim enforcement (Scope='application',
///         ApplicationId matches the requesting client). Missing required
///         claim without a DefaultValue → reject the sign-in with
///         <c>invalid_request</c>; with a DefaultValue → silently emit the
///         default in the token.</item>
///   <item>Per-definition destination control — <c>EmitOnIdToken</c> /
///         <c>EmitOnAccessToken</c> override the default (both-tokens)
///         destination set assigned in
///         <see cref="IdentityPrincipalBuilder"/>.</item>
/// </list>
///
/// Runs AFTER <c>AttachClaimMapperClaims</c> so any mapper-emitted claim
/// that matches a definition gets its destinations rewritten too. Skips for
/// client_credentials grants (no user, nothing to enforce).
/// </summary>
internal sealed class AttachClaimDefinitionEnforcement
    : IOpenIddictServerHandler<ProcessSignInContext>
{
    private readonly IServiceProvider _sp;
    private readonly ILogger<AttachClaimDefinitionEnforcement> _logger;

    public AttachClaimDefinitionEnforcement(IServiceProvider sp, ILogger<AttachClaimDefinitionEnforcement> logger)
    {
        _sp = sp;
        _logger = logger;
    }

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        CreateBuilder<ProcessSignInContext>()
            .UseScopedHandler<AttachClaimDefinitionEnforcement>()
            // Run AFTER AttachClaimMapperClaims (AttachAuthorization + 500) so any
            // mapper-emitted claim sharing a name with a definition also gets its
            // destinations rewritten. Still before token-mint preparation.
            .SetOrder(OpenIddictServerHandlers.AttachAuthorization.Descriptor.Order + 700)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ProcessSignInContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Principal?.Identity is not ClaimsIdentity identity)
            return;

        // client_credentials → no user → no per-user claim enforcement.
        var internalUid = context.Principal.FindFirst(IdentityPrincipalBuilder.InternalUserIdClaim)?.Value;
        if (string.IsNullOrEmpty(internalUid) || !long.TryParse(internalUid, out var userId) || userId <= 0)
            return;

        var redb = _sp.GetService<IRedbService>();
        if (redb is null)
            return;

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
                _logger.LogWarning(ex,
                    "ClaimDefinitions: failed to resolve application by client_id '{ClientId}'; skipping per-app enforcement", clientId);
            }
        }

        // Pull every relevant definition in a single query.
        // global + (application-scoped for the resolved app, if any).
        var defs = await redb.Query<ClaimDefinitionProps>()
            .Where(d => d.Scope == "global" || (d.Scope == "application" && d.ApplicationId == applicationId))
            .ToListAsync()
            .ConfigureAwait(false);

        // Defensive null-guard: production providers always return a (possibly
        // empty) list, but mocked unit-test queries may not be configured for
        // ClaimDefinitionProps and return null — the handler then silently
        // no-ops which mirrors the empty-list path.
        if (defs is null || defs.Count == 0)
            return;

        // Step 1 — required enforcement (per-app only; global was already validated
        // at user create / update by ClaimSchemaValidator).
        foreach (var defObj in defs)
        {
            var def = defObj.Props;
            if (def.Scope != "application")
                continue;
            if (!def.Required)
                continue;

            var existing = identity.FindFirst(def.ClaimName);
            if (existing is not null && !string.IsNullOrEmpty(existing.Value))
                continue;

            if (!string.IsNullOrEmpty(def.DefaultValue))
            {
                // Apply default into the principal so the token carries it.
                identity.AddClaim(new Claim(def.ClaimName, def.DefaultValue));
                continue;
            }

            _logger.LogWarning(
                "ClaimDefinitions: rejecting issuance — required application claim '{Claim}' missing for user {UserId}, client {ClientId}",
                def.ClaimName, userId, clientId);
            context.Reject(
                error: Errors.InvalidRequest,
                description: $"Required claim '{def.ClaimName}' is missing for application '{clientId}'.");
            return;
        }

        // Step 2 — per-definition destination override. Default in
        // IdentityPrincipalBuilder is BOTH tokens; per-definition flags
        // restrict to one or the other.
        var byName = new Dictionary<string, ClaimDefinitionProps>(StringComparer.Ordinal);
        foreach (var d in defs)
            byName[d.Props.ClaimName] = d.Props;

        foreach (var claim in identity.Claims.ToList())
        {
            if (!byName.TryGetValue(claim.Type, out var def))
                continue;

            var dests = new List<string>(2);
            if (def.EmitOnAccessToken) dests.Add(Destinations.AccessToken);
            if (def.EmitOnIdToken) dests.Add(Destinations.IdentityToken);
            // Both flags off — treat as access_token only (preferable over silent
            // claim drop; operator gets surprising-but-not-broken behaviour).
            if (dests.Count == 0) dests.Add(Destinations.AccessToken);
            claim.SetDestinations(dests.ToArray());
        }
    }
}
