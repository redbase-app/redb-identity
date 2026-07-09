using System.Text.Json;
using Fido2NetLib;
using Microsoft.Extensions.DependencyInjection;
using redb.Core;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// MFA-3: login-flow WebAuthn processor. Two operations:
/// <list type="bullet">
/// <item><description><c>begin</c> \u2014 caller supplies the previously-issued <c>mfa_state</c>
/// (from <c>/login</c>); we issue a fresh WebAuthn challenge and a NEW <c>mfa_state</c>
/// containing the assertion options. The original state remains valid until its TTL so the
/// user can fall back to TOTP/SMS/email if WebAuthn fails.</description></item>
/// <item><description><c>complete</c> \u2014 caller supplies the WebAuthn-flow <c>mfa_state</c>
/// + <c>assertion</c> blob. We verify under <c>SELECT \u2026 FOR UPDATE</c>, then create a
/// session exactly like <see cref="MfaVerifyProcessor"/>.</description></item>
/// </list>
/// </summary>
internal sealed class WebAuthnAssertProcessor : IProcessor
{
    private readonly IServiceProvider _sp;
    private static readonly JsonSerializerOptions s_json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    public WebAuthnAssertProcessor(IServiceProvider sp) => _sp = sp;

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var body = exchange.In.Body as IDictionary<string, object?>;
        var operation = exchange.In.GetHeader<string>("operation") ?? "begin";

        exchange.Out = new Message();
        using var scope = _sp.CreateScope();
        var mfa = scope.ServiceProvider.GetRequiredService<MfaService>();

        var mfaStateToken = GetString(body, "mfa_state");
        if (string.IsNullOrEmpty(mfaStateToken))
        {
            exchange.Out.Body = Error("invalid_request", "Missing mfa_state");
            return;
        }
        var state = mfa.UnprotectState(mfaStateToken!);
        if (state is null)
        {
            exchange.Out.Body = Error("invalid_grant", "MFA session expired or invalid");
            return;
        }

        if (operation == "begin")
        {
            var result = await mfa.BeginWebAuthnAssertionAsync(
                state.UserId, state.Username, state.ReturnUrl, ct);
            if (result is null)
            {
                exchange.Out.Body = Error("no_credentials", "No WebAuthn credentials registered");
                return;
            }
            var (options, newToken) = result.Value;
            exchange.Out.Body = new Dictionary<string, object?>
            {
                ["success"] = true,
                ["options"] = JsonSerializer.SerializeToElement(options, s_json),
                ["mfa_state"] = newToken,
            };
            return;
        }

        if (operation == "complete")
        {
            var assertionRaw = body is not null && body.TryGetValue("assertion", out var v) ? v : null;
            if (assertionRaw is null)
            {
                exchange.Out.Body = Error("invalid_request", "Missing assertion");
                return;
            }

            AuthenticatorAssertionRawResponse? assertion;
            try
            {
                var json = JsonSerializer.Serialize(assertionRaw, s_json);
                assertion = JsonSerializer.Deserialize<AuthenticatorAssertionRawResponse>(json, s_json);
            }
            catch (JsonException ex)
            {
                exchange.Out.Body = Error("invalid_request", $"Malformed assertion: {ex.Message}");
                return;
            }
            if (assertion is null)
            {
                exchange.Out.Body = Error("invalid_request", "assertion could not be parsed");
                return;
            }

            var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
            var timeProvider = scope.ServiceProvider.GetService<TimeProvider>() ?? TimeProvider.System;
            var mfaObjId = await mfa.GetMfaObjectIdAsync(state.UserId, ct);

            (bool ok, string? error) result;
            await using (var tx = await redb.Context.BeginTransactionAsync())
            {
                if (mfaObjId != 0)
                    await redb.LockForUpdateAsync(mfaObjId);
                result = await mfa.CompleteWebAuthnAssertionAsync(state.UserId, assertion, state, ct);
                await tx.CommitAsync();
            }

            if (!result.ok)
            {
                exchange.Properties["identity-event-type"] = result.error == "sign_counter_rollback"
                    ? IdentityAuditEventIds.MfaWebAuthnSignCounterAnomaly
                    : IdentityAuditEventIds.MfaVerifyFailed;
                exchange.Properties["identity-event-data"] = new
                {
                    UserId = state.UserId,
                    Username = state.Username,
                    Reason = result.error,
                };
                exchange.Out.Body = new Dictionary<string, object?>
                {
                    ["success"] = false,
                    ["error"] = result.error ?? "verification_failed",
                    ["mfa_state"] = mfaStateToken,
                };
                return;
            }

            // MFA passed \u2014 create session (parity with MfaVerifyProcessor).
            var sessionService = new SessionService(redb, timeProvider);
            var uaParser = scope.ServiceProvider.GetService<MyCSharp.HttpUserAgentParser.Providers.IHttpUserAgentParserProvider>();
            var device = DeviceMetadataExtractor.Extract(exchange, uaParser);
            var session = await sessionService.CreateAsync(
                state.UserId, applicationObjectId: 0,
                mfaVerified: true, mfaMethod: "webauthn",
                ipAddress: device.IpAddress, userAgent: device.UserAgent, deviceLabel: device.DeviceLabel,
                ct: ct);

            exchange.Out.Body = new Dictionary<string, object?>
            {
                ["success"] = true,
                ["userId"] = state.UserId,
                ["username"] = state.Username,
                ["sessionId"] = session.id,
                ["returnUrl"] = state.ReturnUrl,
            };
            exchange.Properties["identity-event-type"] = IdentityAuditEventIds.MfaWebAuthnAsserted;
            exchange.Properties["identity-event-data"] = new
            {
                UserId = state.UserId,
                Username = state.Username,
                Timestamp = timeProvider.GetUtcNow(),
            };
            return;
        }

        exchange.Out.Body = Error("invalid_operation", $"Unknown operation: {operation}");
    }

    private static string? GetString(IDictionary<string, object?>? body, string key)
        => body is not null && body.TryGetValue(key, out var v) ? v?.ToString() : null;

    private static Dictionary<string, object?> Error(string error, string description) =>
        new()
        {
            ["error"] = error,
            ["error_description"] = description,
        };
}
