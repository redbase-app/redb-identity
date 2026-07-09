using Microsoft.Extensions.DependencyInjection;
using redb.Core;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// Core route processor for MFA TOTP verification.
/// Accepts encrypted <c>mfa_state</c> + TOTP <c>code</c>,
/// verifies via <see cref="MfaService"/>, creates session with <c>mfaVerified=true</c>.
/// </summary>
internal sealed class MfaVerifyProcessor : IProcessor
{
    private readonly IServiceProvider _sp;

    public MfaVerifyProcessor(IServiceProvider sp) => _sp = sp;

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var body = exchange.In.Body as IDictionary<string, object?>;
        var mfaStateToken = body?.TryGetValue("mfa_state", out var s) == true ? s?.ToString() : null;
        var code = body?.TryGetValue("code", out var c) == true ? c?.ToString() : null;

        exchange.Out = new Message();

        if (string.IsNullOrEmpty(mfaStateToken) || string.IsNullOrEmpty(code))
        {
            exchange.Out.Body = new Dictionary<string, object?>
            {
                ["success"] = false,
                ["error"] = "invalid_request",
                ["error_description"] = "Missing mfa_state or code"
            };
            return;
        }

        using var scope = _sp.CreateScope();
        var timeProvider = scope.ServiceProvider.GetService<TimeProvider>() ?? TimeProvider.System;
        var mfaService = scope.ServiceProvider.GetRequiredService<MfaService>();
        var metrics = scope.ServiceProvider.GetService<Metrics.IdentityMetrics>();

        // Decrypt and validate MFA state (includes TTL check)
        var state = mfaService.UnprotectState(mfaStateToken);
        if (state is null)
        {
            exchange.Out.Body = new Dictionary<string, object?>
            {
                ["success"] = false,
                ["error"] = "invalid_grant",
                ["error_description"] = "MFA session expired or invalid"
            };
            return;
        }

        // Dispatch by method: SMS/Email use the OTP code embedded in state; TOTP verifies against stored secret.
        var methodId = string.IsNullOrEmpty(state.OtpMethod) ? "totp" : state.OtpMethod!;

        // Atomic verify (B1):
        // SELECT ... FOR UPDATE on the MFA row, then verify + persist FailedAttempts/Lockout under
        // the same transaction. Serializes concurrent verify attempts for the same user → prevents
        // lost-update of FailedAttempts and bypass of the lockout threshold.
        // The IRedbService used by mfaService is the same scoped instance resolved here, so
        // the lock and any SaveAsync inside VerifyAsync share the same connection/transaction.
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var mfaObjId = await mfaService.GetMfaObjectIdAsync(state.UserId, ct).ConfigureAwait(false);

        bool verified;
        await using (var tx = await redb.Context.BeginTransactionAsync().ConfigureAwait(false))
        {
            if (mfaObjId != 0)
                await redb.LockForUpdateAsync(mfaObjId).ConfigureAwait(false);

            verified = await mfaService.VerifyAsync(state.UserId, methodId, code, state, ct).ConfigureAwait(false);

            // Commit either way: success path persists LastVerifiedAt; failure path persists
            // FailedAttempts++ / LockedUntil. Throwing exceptions still rollback via dispose.
            await tx.CommitAsync().ConfigureAwait(false);
        }

        if (!verified)
        {
            metrics?.MfaVerifications.Add(1,
                new KeyValuePair<string, object?>("method", methodId),
                new KeyValuePair<string, object?>("result", "fail"));
            // Re-encrypt state so the user can retry (state is still valid within TTL)
            exchange.Out.Body = new Dictionary<string, object?>
            {
                ["success"] = false,
                ["error"] = "invalid_code",
                ["error_description"] = "Invalid or expired verification code",
                ["mfa_state"] = mfaStateToken
            };
            return;
        }

        // MFA passed — create session
        long sessionId = 0;
        var sessionService = new SessionService(redb, timeProvider);
        var uaParser = scope.ServiceProvider.GetService<MyCSharp.HttpUserAgentParser.Providers.IHttpUserAgentParserProvider>();
        var device = DeviceMetadataExtractor.Extract(exchange, uaParser);
        var session = await sessionService.CreateAsync(
            state.UserId, applicationObjectId: 0,
            mfaVerified: true, mfaMethod: methodId,
            ipAddress: device.IpAddress, userAgent: device.UserAgent, deviceLabel: device.DeviceLabel,
            ct: ct);
        sessionId = session.id;
        metrics?.MfaVerifications.Add(1,
            new KeyValuePair<string, object?>("method", methodId),
            new KeyValuePair<string, object?>("result", "success"));

        exchange.Out.Body = new Dictionary<string, object?>
        {
            ["success"] = true,
            ["userId"] = state.UserId,
            ["username"] = state.Username,
            ["sessionId"] = sessionId,
            ["returnUrl"] = state.ReturnUrl
        };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.UserLoggedIn;
        exchange.Properties["identity-event-data"] = new
        {
            UserId = state.UserId,
            Username = state.Username,
            MfaMethod = methodId,
            Timestamp = timeProvider.GetUtcNow()
        };
    }
}
