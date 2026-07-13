using System.Text.Json;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using redb.Identity.Core.Services;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Supplements OpenIddict's built-in AttachClaims handler by setting OIDC standard claims
/// that the built-in handler does not populate: name, picture, email_verified, phone_number_verified.
/// Also enriches with group/role claims when those scopes are requested.
/// </summary>
internal sealed class AttachAdditionalUserinfoClaims
    : IOpenIddictServerHandler<HandleUserInfoRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleUserInfoRequestContext>()
            .UseScopedHandler<AttachAdditionalUserinfoClaims>()
            .SetOrder(int.MaxValue - 100_000)
            .Build();

    public async ValueTask HandleAsync(HandleUserInfoRequestContext context)
    {
        if (context.Principal is null)
            return;

        // The full OIDC Core §5.1 `profile` claim set. The suite (oidcc-scope-profile /
        // oidcc-scope-all) diffs userinfo against exactly this list, so emit every one we hold.
        if (context.Principal.HasScope(Scopes.Profile))
        {
            foreach (var type in new[]
                     {
                         Claims.Name, Claims.GivenName, Claims.FamilyName, Claims.MiddleName,
                         Claims.Nickname, Claims.PreferredUsername, Claims.Profile,
                         Claims.Picture, Claims.Website, Claims.Gender, Claims.Birthdate,
                         Claims.Zoneinfo, Claims.Locale
                     })
            {
                var value = context.Principal.GetClaim(type);
                if (!string.IsNullOrEmpty(value))
                    context.Claims[type] = value;
            }

            // updated_at is a JSON NUMBER (seconds since the epoch), not a string — emit it typed,
            // otherwise it would go out quoted via the generic custom-claim copy below.
            var updatedAt = context.Principal.GetClaim(Claims.UpdatedAt);
            if (!string.IsNullOrEmpty(updatedAt) && long.TryParse(updatedAt, out var epoch))
                context.Claims[Claims.UpdatedAt] = epoch;
        }

        if (context.Principal.HasScope(Scopes.Email))
        {
            var emailVerified = context.Principal.GetClaim(Claims.EmailVerified);
            if (!string.IsNullOrEmpty(emailVerified) && bool.TryParse(emailVerified, out var ev))
                context.EmailVerified = ev;
        }

        if (context.Principal.HasScope(Scopes.Phone))
        {
            var phoneVerified = context.Principal.GetClaim(Claims.PhoneNumberVerified);
            if (!string.IsNullOrEmpty(phoneVerified) && bool.TryParse(phoneVerified, out var pv))
                context.PhoneNumberVerified = pv;
        }

        // Address scope: emit structured JSON from the claim stored by IdentityPrincipalBuilder
        if (context.Principal.HasScope(Scopes.Address))
        {
            var addressJson = context.Principal.GetClaim(Claims.Address);
            if (!string.IsNullOrEmpty(addressJson))
            {
                var addressObj = JsonSerializer.Deserialize<JsonElement>(addressJson);
                context.Claims[Claims.Address] = addressObj;
            }
        }

        // OIDC Core §5.5 — claims the RP named individually via the `claims` parameter, rather than
        // pulling in a whole scope to get one of them. They are gated on that request and nothing
        // else: an RP that asked for `name` with scope=openid gets `name` here, while an RP that
        // asked for nothing still gets no profile data, exactly as before. The scope blocks above
        // may already have emitted some of these — hence TryAdd semantics, not overwrite.
        var requested = context.Principal.GetClaim(IdentityPrincipalBuilder.RequestedUserInfoClaims);
        if (!string.IsNullOrEmpty(requested))
        {
            foreach (var type in requested.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                if (context.Claims.ContainsKey(type)) continue;

                var value = context.Principal.GetClaim(type);
                if (string.IsNullOrEmpty(value)) continue;

                // Same JSON typing rules as the scope path (§5.1): numbers stay numbers, booleans
                // stay booleans, address stays an object. A claim's type must not depend on which
                // mechanism the RP used to ask for it.
                context.Claims[type] = type switch
                {
                    Claims.UpdatedAt when long.TryParse(value, out var epoch) => epoch,
                    Claims.EmailVerified or Claims.PhoneNumberVerified
                        when bool.TryParse(value, out var flag) => flag,
                    Claims.Address => JsonSerializer.Deserialize<JsonElement>(value),
                    _ => value
                };
            }
        }

        // Custom (RP-defined) claims: copy them from the access-token principal into userinfo.
        //
        // This used to skip only a short list of "standard" claims and forward EVERYTHING else —
        // which quietly leaked the token's own plumbing into the userinfo response: OpenIddict's
        // internals (oi_tkn_id / oi_tkn_typ / oi_scp / oi_prst / oi_crt_dt / oi_exp_dt) and the JWT
        // protocol claims (jti, exp, iat, iss, aud, azp, at_hash, client_id...). Those describe the
        // TOKEN, not the end-user; userinfo (OIDC Core §5.3) must return the user's claims only.
        // An RP has no business learning our token-store ids or expiry bookkeeping.
        //
        // So: skip anything already emitted above, anything OpenIddict-internal (oi_ prefix), and
        // the token/protocol claims. What's left is exactly what this handler was meant for — the
        // RP's own custom claims (e.g. redb:user_id, tenant, department).
        if (context.Principal.Identity is System.Security.Claims.ClaimsIdentity identity)
        {
            var alreadyEmitted = new HashSet<string>(new[]
            {
                Claims.Subject,
                // profile scope (OIDC Core §5.1) — emitted above, typed where it matters
                Claims.Name, Claims.GivenName, Claims.FamilyName, Claims.MiddleName,
                Claims.Nickname, Claims.PreferredUsername, Claims.Profile, Claims.Picture,
                Claims.Website, Claims.Gender, Claims.Birthdate, Claims.Zoneinfo,
                Claims.Locale, Claims.UpdatedAt,
                // email / phone / address scopes
                Claims.Email, Claims.EmailVerified, Claims.PhoneNumber,
                Claims.PhoneNumberVerified, Claims.Address,
                GroupClaimsResolver.GroupsClaim, GroupClaimsResolver.RolesClaim,
                GroupClaimsResolver.OrgClaim, "scope",
                // Our own §5.5 bookkeeping — it records what the RP asked for, it is not a claim
                // about the user, and userinfo (§5.3) returns the user's claims only.
                IdentityPrincipalBuilder.RequestedUserInfoClaims
            });

            // Claims that describe the token / the protocol, never the user.
            var tokenPlumbing = new HashSet<string>(new[]
            {
                Claims.JwtId, Claims.ExpiresAt, Claims.IssuedAt, Claims.NotBefore,
                Claims.Issuer, Claims.Audience, Claims.AuthorizedParty, Claims.ClientId,
                Claims.AccessTokenHash, Claims.CodeHash, Claims.Nonce, Claims.TokenType,
                Claims.TokenUsage, Claims.Scope
            });

            foreach (var claim in identity.Claims)
            {
                if (string.IsNullOrEmpty(claim.Value)) continue;
                if (alreadyEmitted.Contains(claim.Type)) continue;
                if (tokenPlumbing.Contains(claim.Type)) continue;
                // OpenIddict stamps its own bookkeeping with this prefix (oi_tkn_id, oi_scp, ...).
                if (claim.Type.StartsWith("oi_", StringComparison.Ordinal)) continue;

                context.Claims[claim.Type] = claim.Value;
            }
        }

        // Groups/Roles scope claims: read from principal (set by GroupClaimsResolver)
        if (context.Principal.HasScope(GroupClaimsResolver.GroupsScope))
        {
            var groupClaims = context.Principal.FindAll(GroupClaimsResolver.GroupsClaim)
                .Select(c => c.Value).Distinct().ToArray();
            if (groupClaims.Length > 0)
                context.Claims[GroupClaimsResolver.GroupsClaim] = groupClaims;

            var orgClaim = context.Principal.FindFirst(GroupClaimsResolver.OrgClaim);
            if (orgClaim is not null)
                context.Claims[GroupClaimsResolver.OrgClaim] = orgClaim.Value;
        }

        if (context.Principal.HasScope(GroupClaimsResolver.RolesScope))
        {
            var roleClaims = context.Principal.FindAll(GroupClaimsResolver.RolesClaim)
                .Select(c => c.Value).Distinct().ToArray();
            if (roleClaims.Length > 0)
                context.Claims[GroupClaimsResolver.RolesClaim] = roleClaims;
        }
    }
}
