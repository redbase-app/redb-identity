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

        if (context.Principal.HasScope(Scopes.Profile))
        {
            var name = context.Principal.GetClaim(Claims.Name);
            if (!string.IsNullOrEmpty(name))
                context.Claims[Claims.Name] = name;

            var picture = context.Principal.GetClaim(Claims.Picture);
            if (!string.IsNullOrEmpty(picture))
                context.Claims[Claims.Picture] = picture;
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

        // Custom claims: read from principal (set by IdentityPrincipalBuilder with AccessToken + IdentityToken destinations)
        if (context.Principal.Identity is System.Security.Claims.ClaimsIdentity identity)
        {
            var standardClaims = new HashSet<string>(new[]
            {
                Claims.Subject, Claims.Name, Claims.GivenName, Claims.FamilyName,
                Claims.Picture, Claims.Email, Claims.EmailVerified, Claims.PhoneNumber,
                Claims.PhoneNumberVerified, Claims.Address,
                GroupClaimsResolver.GroupsClaim, GroupClaimsResolver.RolesClaim,
                GroupClaimsResolver.OrgClaim, "scope"
            });

            foreach (var claim in identity.Claims)
            {
                if (!standardClaims.Contains(claim.Type) && !string.IsNullOrEmpty(claim.Value))
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
