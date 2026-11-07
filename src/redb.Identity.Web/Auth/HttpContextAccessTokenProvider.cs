using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using redb.Identity.Client.Auth;

namespace redb.Identity.Web.Auth;

/// <summary>
/// Resolves the OIDC access_token from the current cookie-authenticated session and
/// hands it to <see cref="redb.Identity.Client.Auth.BearerTokenHandler"/>. Used in Web BFF
/// where the user is authenticated via cookie + backchannel OIDC; tokens are stored
/// directly on the cookie ticket via <see cref="AuthenticationProperties"/>.
/// </summary>
public sealed class HttpContextAccessTokenProvider : IAccessTokenProvider
{
    private readonly IHttpContextAccessor _accessor;
    public HttpContextAccessTokenProvider(IHttpContextAccessor accessor) => _accessor = accessor;

    public async Task<string?> GetAccessTokenAsync(CancellationToken ct = default)
    {
        var ctx = _accessor.HttpContext;
        if (ctx?.User?.Identity is not ClaimsIdentity { IsAuthenticated: true })
            return null;

        // Tokens are persisted on the cookie ticket by AuthEndpoints.LoginAsync via
        // AuthenticationProperties.StoreTokens(...).
        return await ctx.GetTokenAsync(CookieAuthenticationDefaults.AuthenticationScheme, "access_token");
    }
}
