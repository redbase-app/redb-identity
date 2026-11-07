using Microsoft.Extensions.DependencyInjection;
using redb.Core;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// Core route processor for the Federation Callback endpoint.
/// Handles the IdP redirect: decrypts state, exchanges authorization code for tokens,
/// resolves/provisions local user, creates session, and returns redirect data.
/// </summary>
internal sealed class FederationCallbackProcessor : IProcessor
{
    private readonly IServiceProvider _sp;

    public FederationCallbackProcessor(IServiceProvider sp) => _sp = sp;

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var body = exchange.In.Body as IDictionary<string, object?>;
        var code = body?.TryGetValue("code", out var c) == true ? c?.ToString() : null;
        var stateParam = body?.TryGetValue("state", out var s) == true ? s?.ToString() : null;
        var errorParam = body?.TryGetValue("error", out var ep) == true ? ep?.ToString() : null;
        var callbackUrl = body?.TryGetValue("callbackUrl", out var cb) == true ? cb?.ToString() : null;

        // IdP returned an error (user denied consent, etc.)
        if (!string.IsNullOrEmpty(errorParam))
        {
            var errorDesc = body?.TryGetValue("error_description", out var ed) == true ? ed?.ToString() : null;
            exchange.Out = new Message();
            exchange.Out.Body = new Dictionary<string, object?>
            {
                ["success"] = false,
                ["error"] = errorParam,
                ["error_description"] = errorDesc ?? "External authentication failed."
            };
            return;
        }

        if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(stateParam))
        {
            exchange.Out = new Message();
            exchange.Out.Body = new Dictionary<string, object?>
            {
                ["success"] = false,
                ["error"] = "invalid_request",
                ["error_description"] = "Missing 'code' or 'state' parameter."
            };
            return;
        }

        // Decrypt and validate state (CSRF + replay protection via TTL + one-time-use jti + optional browser-binding)
        var stateProtector = _sp.GetRequiredService<FederationStateProtector>();
        var bindingSecret = exchange.Properties.TryGetValue("federation-binding-secret", out var bs)
            ? bs?.ToString()
            : null;
        var timeProvider = _sp.GetService<TimeProvider>() ?? TimeProvider.System;
        var (state, failure) = await stateProtector.UnprotectAsync(stateParam, bindingSecret, ct).ConfigureAwait(false);

        if (state is null)
        {
            var error = failure switch
            {
                FederationStateValidationFailure.Expired => "invalid_state",
                FederationStateValidationFailure.AlreadyUsed => "invalid_state",
                FederationStateValidationFailure.BindingMismatch => "invalid_state",
                _ => "invalid_state",
            };
            var description = failure switch
            {
                FederationStateValidationFailure.Expired => "State parameter is expired.",
                FederationStateValidationFailure.AlreadyUsed => "State parameter has already been used.",
                FederationStateValidationFailure.BindingMismatch => "Browser-binding cookie missing or mismatched.",
                _ => "State parameter is invalid or expired.",
            };
            exchange.Properties["identity-event-type"] = IdentityAuditEventIds.FederationStateValidationFailed;
            exchange.Properties["identity-event-data"] = new
            {
                Reason = failure.ToString(),
                Timestamp = timeProvider.GetUtcNow(),
            };
            exchange.Out = new Message();
            exchange.Out.Body = new Dictionary<string, object?>
            {
                ["success"] = false,
                ["error"] = error,
                ["error_description"] = description,
            };
            return;
        }

        // Find the federation provider
        var providers = _sp.GetServices<IFederatedAuthProvider>();
        var provider = providers.FirstOrDefault(p => p.ProviderId == state.ProviderId);

        if (provider is null)
        {
            exchange.Out = new Message();
            exchange.Out.Body = new Dictionary<string, object?>
            {
                ["success"] = false,
                ["error"] = "invalid_request",
                ["error_description"] = $"Unknown federation provider '{state.ProviderId}'."
            };
            return;
        }

        // Exchange authorization code for tokens + validate id_token
        var extResult = await provider.HandleCallbackAsync(
            code, callbackUrl ?? "", state.CodeVerifier, state.Nonce, ct).ConfigureAwait(false);

        if (extResult is null || !extResult.Succeeded)
        {
            exchange.Out = new Message();
            exchange.Out.Body = new Dictionary<string, object?>
            {
                ["success"] = false,
                ["error"] = "access_denied",
                ["error_description"] = extResult?.ErrorMessage ?? "Token exchange or validation failed."
            };
            return;
        }

        // Resolve or provision user via LoginService (reverse lookup by value_string)
        using var scope = _sp.CreateScope();
        var loginService = scope.ServiceProvider.GetRequiredService<LoginService>();

        // H8 (DoD §4 gap (b)): link mode — when the challenge embedded a LinkUserId,
        // the callback adds the federated identity to the already-known user instead of
        // performing a login. The link must NOT mint a session; it just records the link
        // and returns success metadata to the front-end.
        if (state.LinkUserId is long linkUserId)
        {
            try
            {
                await loginService.LinkFederatedIdentityAsync(linkUserId, state.ProviderId, extResult, ct)
                    .ConfigureAwait(false);
            }
            catch (InvalidOperationException ex)
            {
                exchange.Out = new Message();
                exchange.Out.Body = new Dictionary<string, object?>
                {
                    ["success"] = false,
                    ["error"] = "link_conflict",
                    ["error_description"] = ex.Message,
                    ["providerId"] = state.ProviderId,
                };
                return;
            }

            exchange.Out = new Message();
            exchange.Out.Body = new Dictionary<string, object?>
            {
                ["success"] = true,
                ["linked"] = true,
                ["userId"] = linkUserId,
                ["providerId"] = state.ProviderId,
                ["externalSub"] = extResult.ExternalId,
                ["returnUrl"] = state.ReturnUrl,
            };

            exchange.Properties["identity-event-type"] = IdentityAuditEventIds.FederatedIdentityLinked;
            exchange.Properties["identity-event-data"] = new
            {
                UserId = linkUserId,
                ProviderId = state.ProviderId,
                ExternalSub = extResult.ExternalId,
                Email = extResult.Email,
                Timestamp = timeProvider.GetUtcNow()
            };
            return;
        }

        var loginResult = await loginService.ResolveFederatedUserAsync(
            state.ProviderId, extResult, ct).ConfigureAwait(false);

        if (!loginResult.Succeeded)
        {
            // H8 (DoD §4 gap (c)): explicit email-conflict path emits a distinct error
            // code so the front-end can route to a "log in locally and link your social
            // account" page instead of showing a generic access_denied message.
            if (loginResult.IsEmailConflict)
            {
                exchange.Out = new Message();
                exchange.Out.Body = new Dictionary<string, object?>
                {
                    ["success"] = false,
                    ["error"] = "email_conflict",
                    ["error_description"] = loginResult.ErrorMessage,
                    ["conflictEmail"] = loginResult.ConflictEmail,
                    ["providerId"] = loginResult.ConflictProviderId,
                    ["externalSub"] = loginResult.ConflictExternalSub,
                    ["returnUrl"] = state.ReturnUrl,
                };

                exchange.Properties["identity-event-type"] = IdentityAuditEventIds.FederatedEmailConflict;
                exchange.Properties["identity-event-data"] = new
                {
                    ProviderId = loginResult.ConflictProviderId,
                    ExternalSub = loginResult.ConflictExternalSub,
                    Email = loginResult.ConflictEmail,
                    Timestamp = timeProvider.GetUtcNow()
                };
                return;
            }

            exchange.Out = new Message();
            exchange.Out.Body = new Dictionary<string, object?>
            {
                ["success"] = false,
                ["error"] = "access_denied",
                ["error_description"] = loginResult.ErrorMessage
            };
            return;
        }

        // Create session (same pattern as LoginProcessor)
        long sessionId = 0;
        var redb = scope.ServiceProvider.GetService<IRedbService>();
        if (redb is not null)
        {
            var sessionService = new SessionService(redb, timeProvider);
            var uaParser = scope.ServiceProvider.GetService<MyCSharp.HttpUserAgentParser.Providers.IHttpUserAgentParserProvider>();
            var device = DeviceMetadataExtractor.Extract(exchange, uaParser);
            var session = await sessionService.CreateAsync(
                loginResult.UserId, applicationObjectId: 0,
                ipAddress: device.IpAddress, userAgent: device.UserAgent, deviceLabel: device.DeviceLabel,
                ct: ct);
            sessionId = session.id;
        }

        exchange.Out = new Message();
        exchange.Out.Body = new Dictionary<string, object?>
        {
            ["success"] = true,
            ["userId"] = loginResult.UserId,
            ["username"] = loginResult.Username,
            ["sessionId"] = sessionId,
            ["returnUrl"] = state.ReturnUrl
        };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.FederatedUserLoggedIn;
        exchange.Properties["identity-event-data"] = new
        {
            UserId = loginResult.UserId,
            Username = loginResult.Username,
            ProviderId = state.ProviderId,
            Timestamp = timeProvider.GetUtcNow()
        };
    }
}
