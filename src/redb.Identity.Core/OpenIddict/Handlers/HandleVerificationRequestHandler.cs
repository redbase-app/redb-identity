using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using redb.Core;
using redb.Identity.Core.Services;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerDescriptor;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Handles <see cref="HandleEndUserVerificationRequestContext"/> for the Device Code Flow (RFC 8628 §3.3).
/// Authenticates the end-user and builds a full <see cref="ClaimsPrincipal"/> that OpenIddict
/// associates with the pending device authorization.
/// </summary>
/// <remarks>
/// <para>RFC 8628 §3.3 leaves end-user authentication on the verification endpoint to the
/// implementation. Two paths are supported, tried in this order:</para>
/// <list type="number">
///   <item>
///     <description>
///       <b>Bearer access_token</b> — when the request carries an <c>Authorization: Bearer …</c>
///       header (forwarded into the route as the <c>access_token</c> exchange header by
///       <c>HttpIdentityProcessors.ExtractBearerToken</c>), the JWT is validated locally
///       against the host's own signing keys, the <c>sub</c> claim is resolved to a user,
///       and the principal is built via <see cref="IUserProfileService"/>. This is the
///       BFF-relayed flow: the front-end is already authenticated via a session cookie that
///       carries a host-issued access_token, and re-prompting for credentials would be
///       both redundant and a worse UX.
///     </description>
///   </item>
///   <item>
///     <description>
///       <b>Username + password</b> — direct host-UI flow (no prior session, no BFF), per
///       RFC 8628 §3.3 the user authenticates on the verification endpoint by submitting
///       credentials in the form body. Delegates to <see cref="LoginService"/>.
///     </description>
///   </item>
/// </list>
/// <para>If neither is present the handler rejects with <see cref="Errors.LoginRequired"/>.</para>
/// </remarks>
internal sealed class HandleVerificationRequestHandler
    : IOpenIddictServerHandler<HandleEndUserVerificationRequestContext>
{
    private readonly IServiceProvider _sp;
    private readonly IOptionsMonitor<OpenIddictServerOptions> _serverOptions;
    private readonly ILogger<HandleVerificationRequestHandler> _logger;
    private static readonly JsonWebTokenHandler _tokenHandler = new();

    public HandleVerificationRequestHandler(
        IServiceProvider sp,
        IOptionsMonitor<OpenIddictServerOptions> serverOptions,
        ILogger<HandleVerificationRequestHandler> logger)
    {
        _sp = sp;
        _serverOptions = serverOptions;
        _logger = logger;
    }

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        CreateBuilder<HandleEndUserVerificationRequestContext>()
            .UseScopedHandler<HandleVerificationRequestHandler>()
            .SetOrder(100_000)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(HandleEndUserVerificationRequestContext context)
    {
        var scopes = context.Principal?.GetScopes() ?? [];
        var scopeList = scopes as IEnumerable<string>;

        // Path 1 (RFC 8628 §3.3 — BFF-relayed): a host-issued access_token authenticates
        // the end-user without re-prompting for credentials.
        var bearerPrincipal = await TryBuildPrincipalFromBearerAsync(context, scopeList)
            .ConfigureAwait(false);
        if (bearerPrincipal is not null)
        {
            MergeIntoContextPrincipal(context, bearerPrincipal);
            _logger.LogDebug(
                "Device verification authorized via bearer access_token (sub={Sub})",
                bearerPrincipal.FindFirst(Claims.Subject)?.Value
                    ?? bearerPrincipal.FindFirst("sub")?.Value);
            return;
        }

        // Path 2 (RFC 8628 §3.3 — direct host-UI flow): form-based credentials.
        var username = (string?)context.Request["username"];
        var password = (string?)context.Request["password"];

        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
        {
            context.Reject(
                error: Errors.LoginRequired,
                description: "User authentication is required. Provide username and password, or an Authorization: Bearer access_token.");
            return;
        }

        var loginService = _sp.GetRequiredService<LoginService>();
        var result = await loginService.AuthenticateAsync(username, password);

        if (!result.Succeeded)
        {
            _logger.LogWarning("Device verification denied: {Error}", result.ErrorMessage);
            // C14 / SEC-A20: generic error to defeat account enumeration on the
            // device-code verification endpoint.
            context.Reject(
                error: Errors.AccessDenied,
                description: "Invalid credentials.");
            return;
        }

        // Build a full principal with OIDC claims (profile, address, custom claims, groups/roles)
        ClaimsPrincipal fullPrincipal;
        var profileService = _sp.GetService<IUserProfileService>();
        if (profileService is not null)
        {
            fullPrincipal = await profileService.BuildPrincipalAsync(
                result.User!.Id, scopeList).ConfigureAwait(false)
                ?? IdentityPrincipalBuilder.Build(result.User!, result.SubjectGuid, result.OidcProps, scopeList);
        }
        else
        {
            // Fallback: manual build (degraded mode without DI)
            fullPrincipal = IdentityPrincipalBuilder.Build(result.User!, result.SubjectGuid, result.OidcProps, scopeList);
            var redb = _sp.GetService<IRedbService>();
            if (redb is not null)
            {
                var resolver = new GroupClaimsResolver(redb);
                await resolver.EnrichPrincipalAsync(fullPrincipal, result.User!.Id, scopeList)
                    .ConfigureAwait(false);
            }
        }

        MergeIntoContextPrincipal(context, fullPrincipal);

        _logger.LogDebug(
            "User '{Username}' (id={UserId}) authorized device code",
            username, result.UserId);
    }

    /// <summary>
    /// Validates a host-issued JWT access_token (if present) and builds a principal for the
    /// resolved <c>sub</c>. Returns <c>null</c> when no token is present or validation fails;
    /// the caller falls through to the form-credentials path (or rejects with login_required).
    /// </summary>
    /// <remarks>
    /// Mirrors the validation parameters used by <c>LogoutProcessor.ValidateIdTokenHintAsync</c>
    /// (RP-Initiated Logout id_token_hint validation): trust the host's own signing keys,
    /// require valid lifetime, allow 5 minute clock skew, skip audience validation (the
    /// token's audience is the original API resource, not this endpoint).
    /// </remarks>
    private async Task<ClaimsPrincipal?> TryBuildPrincipalFromBearerAsync(
        HandleEndUserVerificationRequestContext context,
        IEnumerable<string> scopes)
    {
        var exchange = context.Transaction.GetRouteExchange();
        if (exchange is null)
            return null;

        // Set upstream by HttpIdentityProcessors.ExtractBearerToken (Authorization: Bearer …
        // header → "access_token" exchange header, "Bearer " prefix already stripped).
        var jwt = exchange.In.GetHeader<string>("access_token");
        if (string.IsNullOrEmpty(jwt))
            return null;

        var opts = _serverOptions.CurrentValue;
        var signingKeys = opts.SigningCredentials.Select(c => c.Key).ToList();
        if (signingKeys.Count == 0)
        {
            _logger.LogWarning(
                "No signing keys configured — cannot validate bearer access_token on /connect/device/verify");
            return null;
        }

        // Accept both forms of the issuer (with and without trailing slash). OpenIddict
        // signs tokens with iss = Issuer.AbsoluteUri (trailing slash on the root); some
        // deployments configure the issuer without a trailing slash. Validate against
        // both so the same handler works in either configuration.
        var issuerString = opts.Issuer?.ToString();
        var validIssuers = new List<string>();
        if (!string.IsNullOrEmpty(issuerString))
        {
            validIssuers.Add(issuerString);
            var trimmed = issuerString.TrimEnd('/');
            if (trimmed != issuerString)
                validIssuers.Add(trimmed);
        }

        var validationParams = new TokenValidationParameters
        {
            ValidIssuers = validIssuers,
            ValidateIssuer = opts.Issuer is not null,
            ValidateAudience = false, // access_token's audience is the API resource, not this endpoint
            ValidateLifetime = true,
            IssuerSigningKeys = signingKeys,
            ValidateIssuerSigningKey = true,
            ClockSkew = TimeSpan.FromMinutes(5)
        };

        TokenValidationResult result;
        try
        {
            result = await _tokenHandler.ValidateTokenAsync(jwt, validationParams).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Bearer access_token validation threw on /connect/device/verify");
            return null;
        }

        if (!result.IsValid)
        {
            _logger.LogWarning(
                "Bearer access_token validation failed on /connect/device/verify: {Error}",
                result.Exception?.Message);
            return null;
        }

        var sub = result.ClaimsIdentity.FindFirst(Claims.Subject)?.Value
                  ?? result.ClaimsIdentity.FindFirst("sub")?.Value;
        // The public sub is now a GUID; the bigint user id rides alongside in
        // the internal redb:user_id access-token claim (see IdentityPrincipalBuilder).
        var internalUid = result.ClaimsIdentity.FindFirst(IdentityPrincipalBuilder.InternalUserIdClaim)?.Value;
        if (string.IsNullOrEmpty(internalUid) || !long.TryParse(internalUid, out var userId))
        {
            _logger.LogWarning(
                "Bearer access_token on /connect/device/verify has missing or non-numeric {Claim} claim (sub={Sub})",
                IdentityPrincipalBuilder.InternalUserIdClaim, sub);
            return null;
        }

        var profileService = _sp.GetService<IUserProfileService>();
        if (profileService is null)
        {
            _logger.LogWarning(
                "IUserProfileService not registered — cannot build bearer principal on /connect/device/verify");
            return null;
        }

        var principal = await profileService
            .BuildPrincipalAsync(userId, scopes)
            .ConfigureAwait(false);

        if (principal is null)
            _logger.LogWarning(
                "Bearer access_token sub={Sub} does not resolve to an enabled user", userId);

        return principal;
    }

    /// <summary>
    /// Merges the freshly built user principal into the context principal. OpenIddict's
    /// built-in <c>AttachUserCodePrincipal</c> runs before this handler and sets
    /// <see cref="HandleEndUserVerificationRequestContext.Principal"/> to a principal that
    /// carries internal claims (authorization id, client id, scopes); we add our user claims
    /// on top so OpenIddict can later associate the device authorization with this user.
    /// </summary>
    private static void MergeIntoContextPrincipal(
        HandleEndUserVerificationRequestContext context,
        ClaimsPrincipal user)
    {
        if (context.Principal?.Identity is ClaimsIdentity existingIdentity)
        {
            var userIdentity = (ClaimsIdentity)user.Identity!;
            foreach (var claim in userIdentity.Claims)
                existingIdentity.AddClaim(claim);
        }
        else
        {
            context.Principal = user;
        }
    }
}
