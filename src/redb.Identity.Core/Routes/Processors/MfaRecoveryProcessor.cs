using Microsoft.Extensions.DependencyInjection;
using redb.Core;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// Core route processor for MFA recovery code verification.
/// Accepts encrypted <c>mfa_state</c> + one-time <c>recovery_code</c>,
/// verifies via <see cref="MfaService.VerifyRecoveryCodeAsync"/>, creates session.
/// The recovery code is consumed (deleted) on success.
/// </summary>
internal sealed class MfaRecoveryProcessor : IProcessor
{
    private readonly IServiceProvider _sp;

    public MfaRecoveryProcessor(IServiceProvider sp) => _sp = sp;

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var body = exchange.In.Body as IDictionary<string, object?>;
        var mfaStateToken = body?.TryGetValue("mfa_state", out var s) == true ? s?.ToString() : null;
        var recoveryCode = body?.TryGetValue("recovery_code", out var c) == true ? c?.ToString() : null;

        exchange.Out = new Message();

        if (string.IsNullOrEmpty(mfaStateToken) || string.IsNullOrEmpty(recoveryCode))
        {
            exchange.Out.Body = new Dictionary<string, object?>
            {
                ["success"] = false,
                ["error"] = "invalid_request",
                ["error_description"] = "Missing mfa_state or recovery_code"
            };
            return;
        }

        using var scope = _sp.CreateScope();
        var timeProvider = scope.ServiceProvider.GetService<TimeProvider>() ?? TimeProvider.System;
        var mfaService = scope.ServiceProvider.GetRequiredService<MfaService>();
        var metrics = scope.ServiceProvider.GetService<Metrics.IdentityMetrics>();

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

        // Atomic consume (B1-recovery): mirrors MfaVerifyProcessor — SELECT ... FOR UPDATE on
        // the MFA row, then verify+consume+persist under one tx. Without this, two concurrent
        // verifies of the same recovery code both read the same RecoveryCodes list, both find
        // the match, both call SaveAsync → last write wins and a single code is "used" twice.
        // The IRedbService resolved here is the same scoped instance used by mfaService, so
        // the lock and the internal SaveAsync share connection/transaction.
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var mfaObjId = await mfaService.GetMfaObjectIdAsync(state.UserId, ct).ConfigureAwait(false);

        bool verified;
        await using (var tx = await redb.Context.BeginTransactionAsync().ConfigureAwait(false))
        {
            if (mfaObjId != 0)
                await redb.LockForUpdateAsync(mfaObjId).ConfigureAwait(false);

            verified = await mfaService.VerifyRecoveryCodeAsync(state.UserId, recoveryCode, ct).ConfigureAwait(false);
            await tx.CommitAsync().ConfigureAwait(false);
        }

        if (!verified)
        {
            metrics?.MfaVerifications.Add(1,
                new KeyValuePair<string, object?>("method", "recovery"),
                new KeyValuePair<string, object?>("result", "fail"));
            exchange.Out.Body = new Dictionary<string, object?>
            {
                ["success"] = false,
                ["error"] = "invalid_code",
                ["error_description"] = "Invalid recovery code",
                ["mfa_state"] = mfaStateToken
            };
            return;
        }

        // Recovery code verified and consumed — create session
        long sessionId = 0;
        {
            var sessionService = new SessionService(redb, timeProvider);
            var uaParser = scope.ServiceProvider.GetService<MyCSharp.HttpUserAgentParser.Providers.IHttpUserAgentParserProvider>();
            var device = DeviceMetadataExtractor.Extract(exchange, uaParser);
            var session = await sessionService.CreateAsync(
                state.UserId, applicationObjectId: 0,
                mfaVerified: true, mfaMethod: "recovery",
                ipAddress: device.IpAddress, userAgent: device.UserAgent, deviceLabel: device.DeviceLabel,
                ct: ct);
            sessionId = session.id;
        }

        metrics?.MfaVerifications.Add(1,
            new KeyValuePair<string, object?>("method", "recovery"),
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
            MfaMethod = "recovery",
            Timestamp = timeProvider.GetUtcNow()
        };
    }
}
