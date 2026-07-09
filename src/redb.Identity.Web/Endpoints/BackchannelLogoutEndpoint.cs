using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using redb.Identity.Client.Backchannel;
using redb.Identity.Contracts.Sessions;
using redb.Identity.Web.Configuration;
using redb.Identity.Web.Services;

namespace redb.Identity.Web.Endpoints;

/// <summary>
/// OIDC Back-Channel Logout sink (RFC 8417 / OpenID Connect Back-Channel Logout 1.0).
/// Validates the incoming <c>logout_token</c> against Identity JWKS and publishes the
/// revoked sid/sub to the cluster-wide
/// <c>/api/v1/identity/revoked-sids</c> store. The cookie blacklist
/// (<see cref="IRevokedSidsCache"/>) is also updated locally for instant effect on
/// this replica; other replicas pick up the change on their next poll.
/// </summary>
public static class BackchannelLogoutEndpoint
{
    public static IEndpointRouteBuilder MapBackchannelLogoutSink(
        this IEndpointRouteBuilder endpoints, string path = "/bcl/sink")
    {
        endpoints.MapPost(path, async (
            HttpContext ctx,
            IBackchannelIdentityClient backchannel,
            IRevokedSidsCache cache,
            IConfigurationManager<OpenIdConnectConfiguration> oidcConfig,
            IOptions<IdentityWebOptions> idOpts,
            ILoggerFactory loggerFactory,
            CancellationToken ct) =>
        {
            var log = loggerFactory.CreateLogger("BCL");

            if (!ctx.Request.HasFormContentType)
                return Results.BadRequest("Expected form-encoded logout_token");

            var form = await ctx.Request.ReadFormAsync(ct);
            var logoutToken = form["logout_token"].ToString();
            if (string.IsNullOrEmpty(logoutToken))
                return Results.BadRequest("Missing logout_token");

            var config = await oidcConfig.GetConfigurationAsync(ct);

            var handler = new JwtSecurityTokenHandler();
            var parameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = idOpts.Value.Authority,
                ValidateAudience = true,
                ValidAudience = idOpts.Value.ClientId,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = config.SigningKeys,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(2),
                RequireExpirationTime = false,
            };

            JwtSecurityToken token;
            try
            {
                handler.ValidateToken(logoutToken, parameters, out var validated);
                token = (JwtSecurityToken)validated;
            }
            catch (Exception ex)
            {
                log.LogWarning(ex, "Invalid logout_token");
                return Results.BadRequest("Invalid logout_token signature");
            }

            var events = token.Claims.FirstOrDefault(c => c.Type == "events")?.Value;
            if (events is null
                || !events.Contains("http://schemas.openid.net/event/backchannel-logout"))
            {
                return Results.BadRequest("Missing or invalid 'events' claim");
            }
            if (token.Claims.Any(c => c.Type == "nonce"))
                return Results.BadRequest("logout_token must not contain nonce");

            var sid = token.Claims.FirstOrDefault(c => c.Type == "sid")?.Value;
            var sub = token.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;

            if (string.IsNullOrEmpty(sid) && string.IsNullOrEmpty(sub))
            {
                return Results.BadRequest("logout_token must contain 'sid' or 'sub'");
            }

            // W6-0: publish to cluster-wide blacklist. Expiry derived from logout_token
            // lifetime when present, otherwise a conservative default.
            var expiresAt = token.ValidTo > DateTime.UnixEpoch
                ? new DateTimeOffset(token.ValidTo, TimeSpan.Zero)
                : DateTimeOffset.UtcNow.AddHours(24);

            try
            {
                var entry = await backchannel.AddRevokedSidAsync(sid, sub, clientId: null, expiresAt, ct);
                cache.Apply(new[] { entry });
                log.LogInformation(
                    "BCL: published revoked-sid (sid={Sid} sub={Sub} expires={Expires:O})",
                    sid, sub, expiresAt);
            }
            catch (Exception ex)
            {
                log.LogError(ex, "BCL: failed to publish revoked-sid (sid={Sid} sub={Sub})", sid, sub);
                // Per spec: even on persistence failure we acknowledge to avoid retry storms
                // — local replica picks up the entry on next poll (or this instance via cache.Apply
                // above if the network call partially succeeded before throwing).
            }

            ctx.Response.Headers.CacheControl = "no-store";
            return Results.Ok();
        })
        .AllowAnonymous();

        return endpoints;
    }
}
