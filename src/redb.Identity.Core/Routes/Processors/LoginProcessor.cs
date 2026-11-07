using Microsoft.Extensions.DependencyInjection;
using redb.Core;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// Core route processor for the Login endpoint.
/// Verifies credentials and returns userId + username in the response
/// (the HTTP facade converts this to a session cookie).
/// </summary>
internal sealed class LoginProcessor : IProcessor
{
    private readonly IServiceProvider _sp;

    public LoginProcessor(IServiceProvider sp) => _sp = sp;

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var body = exchange.In.Body as IDictionary<string, object?>;
        var username = body?.TryGetValue("username", out var u) == true ? u?.ToString() : null;
        var password = body?.TryGetValue("password", out var p) == true ? p?.ToString() : null;
        var returnUrl = body?.TryGetValue("returnUrl", out var r) == true ? r?.ToString() : null;

        using var scope = _sp.CreateScope();
        var timeProvider = scope.ServiceProvider.GetService<TimeProvider>() ?? TimeProvider.System;
        var loginService = scope.ServiceProvider.GetRequiredService<LoginService>();
        var result = await loginService.AuthenticateAsync(username ?? "", password ?? "", ct);

        exchange.Out = new Message();

        if (result.MfaRequired)
        {
            // Password verified but MFA needed — encrypt state, no session
            var stateProtector = scope.ServiceProvider.GetRequiredService<MfaStateProtector>();
            var mfaState = stateProtector.Protect(new MfaState
            {
                Jti = Guid.NewGuid(),
                UserId = result.UserId,
                Username = result.Username,
                Methods = result.MfaMethods!,
                ReturnUrl = returnUrl
            });

            exchange.Out.Body = new Dictionary<string, object?>
            {
                ["success"] = false,
                ["mfa_required"] = true,
                // B9 / BUG-9: do NOT echo the configured MFA methods back to a caller who
                // has only just proved knowledge of the password. The methods are still
                // embedded inside the encrypted mfa_state and can be obtained with a
                // gated round-trip to /mfa/methods (Auth0-style). This avoids leaking
                // factor-mix information to callers who might be probing accounts.
                ["mfa_state"] = mfaState
            };
            return;
        }

        // H10 — password verified but expired. Surface a dedicated flag so the HTTP
        // facade can redirect the browser to the password-change page; we deliberately
        // do NOT create a session here — the user must change the password first.
        if (result.MustChangePassword)
        {
            exchange.Out.Body = new Dictionary<string, object?>
            {
                ["success"] = false,
                ["password_expired"] = true,
                ["userId"] = result.UserId,
                ["username"] = result.Username,
                ["returnUrl"] = returnUrl,
                ["error"] = "password_expired",
                ["error_description"] = "Password has expired and must be changed before signing in."
            };
            return;
        }

        if (result.Succeeded)
        {
            // Create session record at login time (1 session = 1 browser login)
            long sessionId = 0;
            var redb = scope.ServiceProvider.GetService<IRedbService>();
            if (redb is not null)
            {
                var sessionService = new SessionService(redb, timeProvider);
                var uaParser = scope.ServiceProvider.GetService<MyCSharp.HttpUserAgentParser.Providers.IHttpUserAgentParserProvider>();
                var device = DeviceMetadataExtractor.Extract(exchange, uaParser);
                var session = await sessionService.CreateAsync(
                    result.UserId, applicationObjectId: 0,
                    ipAddress: device.IpAddress, userAgent: device.UserAgent, deviceLabel: device.DeviceLabel,
                    ct: ct);
                sessionId = session.id;
            }

            exchange.Out.Body = new Dictionary<string, object?>
            {
                ["success"] = true,
                ["userId"] = result.UserId,
                ["username"] = result.Username,
                ["sessionId"] = sessionId,
                ["returnUrl"] = returnUrl
            };

            exchange.Properties["identity-event-type"] = IdentityAuditEventIds.UserLoggedIn;
            exchange.Properties["identity-event-data"] = new
            {
                UserId = result.UserId,
                Username = result.Username,
                Timestamp = timeProvider.GetUtcNow()
            };
        }
        else
        {
            // C14 / SEC-A20: do NOT echo provider-specific error text back to the caller.
            // ResolveExternalUser may have produced a richer message (e.g. "Account locked
            // by external IdP"), but exposing it here lets an attacker enumerate accounts
            // and probe for state. The actual message is preserved in server logs by
            // LoginService for operator triage.
            exchange.Out.Body = new Dictionary<string, object?>
            {
                ["success"] = false,
                ["error"] = "access_denied",
                ["error_description"] = "Invalid credentials."
            };
        }
    }
}
