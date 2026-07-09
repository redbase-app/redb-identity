using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Validation;
using redb.Core;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Services;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerDescriptor;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Handles <see cref="HandleTokenRequestContext"/> for client_credentials, device_code,
/// password (ROPC), and token exchange (RFC 8693) grant types.
/// For authorization_code and refresh_token, OpenIddict resolves the principal from
/// the stored code/token automatically — no custom handler needed.
/// Note: OpenIddict 6.3.0's built-in AttachPrincipal only handles authorization_code
/// and refresh_token. Device code principal must be copied explicitly.
/// </summary>
internal sealed class HandleTokenRequestHandler : IOpenIddictServerHandler<HandleTokenRequestContext>
{
    private readonly ILogger<HandleTokenRequestHandler> _logger;
    private readonly IServiceProvider _sp;

    public HandleTokenRequestHandler(
        ILogger<HandleTokenRequestHandler> logger,
        IServiceProvider sp)
    {
        _logger = logger;
        _sp = sp;
    }

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        CreateBuilder<HandleTokenRequestContext>()
            .UseScopedHandler<HandleTokenRequestHandler>()
            .SetOrder(OpenIddictServerHandlers.Exchange.AttachPrincipal.Descriptor.Order + 100)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(HandleTokenRequestContext context)
    {
        // OpenIddict 6.3.0's built-in AttachPrincipal only copies the principal for
        // authorization_code and refresh_token grants. For device_code, we need to
        // copy it ourselves from the ValidateTokenRequestContext stored in the transaction.
        if (context.Request.IsDeviceCodeGrantType())
        {
            var validateCtx = context.Transaction.GetProperty<ValidateTokenRequestContext>(
                typeof(ValidateTokenRequestContext).FullName!);

            if (validateCtx?.Principal is not null)
            {
                context.Principal ??= validateCtx.Principal;
                _logger.LogDebug("Attached device code principal for token exchange");
            }

            return;
        }

        // ROPC: grant_type=password (opt-in via EnablePasswordFlow)
        if (context.Request.IsPasswordGrantType())
        {
            var loginService = _sp.GetService<LoginService>();
            if (loginService is null)
            {
                context.Reject(
                    error: Errors.UnsupportedGrantType,
                    description: "The password grant type is not configured.");
                return;
            }

            var username = context.Request.Username;
            var password = context.Request.Password;

            var result = await loginService.AuthenticateAsync(username ?? "", password ?? "");
            if (result.MustChangePassword)
            {
                // H10 — ROPC cannot complete a password-change ceremony, so reject. The
                // standard OAuth error vocabulary doesn't have a password-expired code,
                // so use invalid_grant + a precise description that resource owners can
                // surface to the user.
                context.Reject(
                    error: Errors.InvalidGrant,
                    description: "Password expired; change required before token issuance.");
                return;
            }
            if (!result.Succeeded)
            {
                // C14 / SEC-A20: do NOT echo provider-specific failure text. The original
                // reason is in server logs; surface a generic message to defeat enumeration.
                context.Reject(
                    error: Errors.AccessDenied,
                    description: "Invalid credentials.");
                return;
            }

            var profileService = _sp.GetService<IUserProfileService>();
            if (profileService is not null)
            {
                // Fast path: LoginService already loaded IRedbUser + UserProps + subject GUID.
                // Skip when UserProps is missing (legacy / freshly-created user with no envelope)
                // or when value_guid hasn't been issued yet — slow path lazy-creates and persists.
                if (result.OidcProps is not null && result.SubjectGuid != Guid.Empty)
                {
                    context.Principal = await profileService.BuildPrincipalAsync(
                        result.User!, result.OidcProps, result.SubjectGuid,
                        context.Request.GetScopes()).ConfigureAwait(false);
                }
                else
                {
                    context.Principal = await profileService.BuildPrincipalAsync(
                        result.User!.Id, context.Request.GetScopes()).ConfigureAwait(false);
                }
            }
            else
            {
                // Fallback if DI not configured (degraded mode)
                context.Principal = IdentityPrincipalBuilder.Build(
                    result.User!, result.SubjectGuid, result.OidcProps, context.Request.GetScopes());
            }

            _logger.LogDebug("Issued ClaimsPrincipal for password grant: {Username}", username);
            return;
        }

        // Only handle client_credentials — auth_code and refresh_token are handled
        // by OpenIddict's built-in handlers that restore the principal from the stored token/code
        if (context.Request.GrantType == "urn:ietf:params:oauth:grant-type:token-exchange")
        {
            await HandleTokenExchangeAsync(context);
            return;
        }

        if (!context.Request.IsClientCredentialsGrantType())
            return;

        var identity = new ClaimsIdentity(
            authenticationType: "OpenIddict.Server",
            nameType: Claims.Name,
            roleType: Claims.Role);

        identity.SetClaim(Claims.Subject, context.Request.ClientId);
        identity.SetScopes(context.Request.GetScopes());

        // Set destinations so claims appear in the access token
        foreach (var claim in identity.Claims)
            claim.SetDestinations(new[] { Destinations.AccessToken });

        context.Principal = new ClaimsPrincipal(identity);

        _logger.LogDebug("Issued ClaimsPrincipal for client_credentials: {ClientId}",
            context.Request.ClientId);
    }

    /// <summary>
    /// Handles the Token Exchange grant type (RFC 8693).
    /// Validates the subject_token via OpenIddict Validation (server-local),
    /// then builds a new principal for the exchanged token. Supports delegation
    /// (with <c>act</c> claim chain) and optionally impersonation.
    /// </summary>
    private async Task HandleTokenExchangeAsync(HandleTokenRequestContext context)
    {
        const string AccessTokenTypeId = "urn:ietf:params:oauth:token-type:access_token";
        const string ActClaimType = "act";

        var options = _sp.GetRequiredService<IOptions<RedbIdentityOptions>>().Value;

        // ── 1. Extract subject_token ──
        var subjectToken = (string?)context.Request["subject_token"];
        if (string.IsNullOrEmpty(subjectToken))
        {
            context.Reject(Errors.InvalidRequest, "The subject_token parameter is required.");
            return;
        }

        var subjectTokenType = (string?)context.Request["subject_token_type"];
        if (string.IsNullOrEmpty(subjectTokenType))
        {
            context.Reject(Errors.InvalidRequest, "The subject_token_type parameter is required.");
            return;
        }

        // We only accept access tokens as subject_token
        if (subjectTokenType != AccessTokenTypeId)
        {
            context.Reject(Errors.InvalidRequest,
                $"The subject_token_type '{subjectTokenType}' is not supported. " +
                $"Only '{AccessTokenTypeId}' is accepted.");
            return;
        }

        // ── 2. Validate subject_token via OpenIddict Validation (server-local) ──
        var factory = _sp.GetRequiredService<IOpenIddictValidationFactory>();
        var dispatcher = _sp.GetRequiredService<IOpenIddictValidationDispatcher>();

        var transaction = await factory.CreateTransactionAsync();
        transaction.Properties[Routes.Processors.ManagementBearerAuthProcessor.TokenPropertyKey] = subjectToken;

        var authContext = new OpenIddictValidationEvents.ProcessAuthenticationContext(transaction);
        await dispatcher.DispatchAsync(authContext);

        if (authContext.IsRejected || authContext.AccessTokenPrincipal is null)
        {
            context.Reject(Errors.InvalidGrant,
                authContext.ErrorDescription ?? "The subject_token is invalid or expired.");
            return;
        }

        var subjectPrincipal = authContext.AccessTokenPrincipal;
        var originalSubject = subjectPrincipal.GetClaim(Claims.Subject);

        if (string.IsNullOrEmpty(originalSubject))
        {
            context.Reject(Errors.InvalidGrant, "The subject_token does not contain a valid subject claim.");
            return;
        }

        // ── 3. Determine requested_token_type (default: access_token) ──
        var requestedTokenType = (string?)context.Request["requested_token_type"];
        if (!string.IsNullOrEmpty(requestedTokenType) &&
            requestedTokenType != AccessTokenTypeId)
        {
            context.Reject(Errors.InvalidRequest,
                $"The requested_token_type '{requestedTokenType}' is not supported. " +
                $"Only '{AccessTokenTypeId}' is allowed.");
            return;
        }

        // ── 4. Check actor_token (optional — for delegation) ──
        var actorToken = (string?)context.Request["actor_token"];
        ClaimsPrincipal? actorPrincipal = null;

        if (!string.IsNullOrEmpty(actorToken))
        {
            var actorTokenType = (string?)context.Request["actor_token_type"];
            if (string.IsNullOrEmpty(actorTokenType) ||
                actorTokenType != AccessTokenTypeId)
            {
                context.Reject(Errors.InvalidRequest,
                    "When actor_token is provided, actor_token_type must be " +
                    $"'{AccessTokenTypeId}'.");
                return;
            }

            var actorTransaction = await factory.CreateTransactionAsync();
            actorTransaction.Properties[Routes.Processors.ManagementBearerAuthProcessor.TokenPropertyKey] = actorToken;

            var actorAuthCtx = new OpenIddictValidationEvents.ProcessAuthenticationContext(actorTransaction);
            await dispatcher.DispatchAsync(actorAuthCtx);

            if (actorAuthCtx.IsRejected || actorAuthCtx.AccessTokenPrincipal is null)
            {
                context.Reject(Errors.InvalidGrant,
                    actorAuthCtx.ErrorDescription ?? "The actor_token is invalid or expired.");
                return;
            }

            actorPrincipal = actorAuthCtx.AccessTokenPrincipal;
        }

        // ── 5. Determine delegation vs impersonation ──
        // If actor_token is provided → delegation (act claim chain)
        // If no actor_token → impersonation (only if allowed)
        var isDelegation = actorPrincipal is not null;
        if (!isDelegation && !options.TokenExchangeAllowImpersonation)
        {
            // Without actor_token and impersonation disabled, the requesting client acts as the actor
            isDelegation = true;
        }

        // ── 6. Check delegation chain depth ──
        if (isDelegation && options.TokenExchangeMaxDelegationDepth > 0)
        {
            var existingActClaim = subjectPrincipal.GetClaim(ActClaimType);
            var depth = CountActChainDepth(existingActClaim);
            if (depth >= options.TokenExchangeMaxDelegationDepth)
            {
                context.Reject(Errors.InvalidGrant,
                    $"The delegation chain depth ({depth}) exceeds the maximum allowed ({options.TokenExchangeMaxDelegationDepth}).");
                return;
            }
        }

        // ── 7. Build new principal ──
        var newIdentity = new ClaimsIdentity(
            authenticationType: "OpenIddict.Server",
            nameType: Claims.Name,
            roleType: Claims.Role);

        // Carry over subject from the original token
        newIdentity.SetClaim(Claims.Subject, originalSubject);

        // Carry over name if present
        var originalName = subjectPrincipal.GetClaim(Claims.Name);
        if (!string.IsNullOrEmpty(originalName))
            newIdentity.SetClaim(Claims.Name, originalName);

        // Use requested scopes if provided, otherwise carry over original scopes
        var requestedScopes = context.Request.GetScopes();
        if (requestedScopes.Length > 0)
        {
            // Requested scopes must be a subset of the original token's scopes
            var originalScopes = subjectPrincipal.GetScopes();
            var unauthorized = requestedScopes.Except(originalScopes).ToArray();
            if (unauthorized.Length > 0)
            {
                context.Reject(Errors.InvalidScope,
                    $"The requested scope(s) [{string.Join(", ", unauthorized)}] " +
                    "are not present in the subject_token.");
                return;
            }

            newIdentity.SetScopes(requestedScopes);
        }
        else
        {
            newIdentity.SetScopes(subjectPrincipal.GetScopes());
        }

        // ── 8. Add act claim for delegation ──
        if (isDelegation)
        {
            var actorSub = actorPrincipal?.GetClaim(Claims.Subject) ?? context.Request.ClientId;
            var actorClientId = context.Request.ClientId;

            // Build the act claim as a JSON object per RFC 8693 §4.1
            var actClaim = new Dictionary<string, object?> { ["sub"] = actorSub };
            if (actorSub != actorClientId)
                actClaim["client_id"] = actorClientId;

            // Chain existing act claim if present (delegation chain)
            var existingAct = subjectPrincipal.GetClaim(ActClaimType);
            if (!string.IsNullOrEmpty(existingAct))
                actClaim["act"] = JsonSerializer.Deserialize<object>(existingAct);

            var actJson = JsonSerializer.Serialize(actClaim);
            newIdentity.AddClaim(new Claim(ActClaimType, actJson, "JSON"));
        }

        // Set destinations
        foreach (var claim in newIdentity.Claims)
        {
            if (claim.Type == ActClaimType)
                claim.SetDestinations(Destinations.AccessToken, Destinations.IdentityToken);
            else
                claim.SetDestinations(Destinations.AccessToken);
        }

        context.Principal = new ClaimsPrincipal(newIdentity);

        _logger.LogDebug(
            "Token exchange completed: subject={Subject}, client={ClientId}, delegation={IsDelegation}",
            originalSubject, context.Request.ClientId, isDelegation);
    }

    /// <summary>
    /// Counts the depth of an <c>act</c> claim chain (nested JSON objects).
    /// </summary>
    private static int CountActChainDepth(string? actClaimJson)
    {
        if (string.IsNullOrEmpty(actClaimJson))
            return 0;

        var depth = 1;
        try
        {
            using var doc = JsonDocument.Parse(actClaimJson);
            var element = doc.RootElement;
            while (element.TryGetProperty("act", out var nested))
            {
                depth++;
                element = nested;
            }
        }
        catch (JsonException)
        {
            // Malformed act claim — treat as depth 1
        }

        return depth;
    }
}
