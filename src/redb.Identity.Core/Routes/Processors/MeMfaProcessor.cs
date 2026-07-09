using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// H3 (v1.0 DoD §6): self-service MFA management backing <c>/me/mfa/*</c>. Mirrors
/// <see cref="MfaSetupProcessor"/> operation-by-operation but injects the caller's
/// user id from <c>identity:management-subject</c> instead of reading it from the
/// request body — under no circumstances may a user enroll, confirm, disable, or
/// regenerate codes for someone else's account through this surface. Admin parity
/// remains under <see cref="MfaSetupProcessor"/> with body.userId.
/// </summary>
internal sealed class MeMfaProcessor : IProcessor
{
    private readonly IServiceProvider _sp;

    public MeMfaProcessor(IServiceProvider sp) => _sp = sp;

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var callerId = MeProcessorHelpers.TryGetCallerUserId(exchange);
        if (callerId is null)
        {
            MeProcessorHelpers.Reject(exchange, 401, "invalid_token",
                $"The access token does not carry a numeric subject claim required for self-service APIs (got subject={MeProcessorHelpers.GetRawCallerSubject(exchange) ?? "<null>"}).");
            return;
        }

        var operation = exchange.In.GetHeader<string>("operation")
            ?? throw new InvalidOperationException("Missing 'operation' header");

        exchange.Out = new Message();

        using var scope = _sp.CreateScope();
        var mfaService = scope.ServiceProvider.GetRequiredService<MfaService>();
        var body = exchange.In.Body as IDictionary<string, object?>;

        switch (operation)
        {
            case "status":
                await Status(mfaService, callerId.Value, exchange, ct);
                break;
            case "setup":
                await Setup(mfaService, callerId.Value, body, exchange, ct);
                break;
            case "confirm":
                await Confirm(mfaService, callerId.Value, body, exchange, ct);
                break;
            case "disable":
                await Disable(mfaService, callerId.Value, body, exchange, ct);
                break;
            case "regenerate-recovery":
                await RegenerateRecovery(mfaService, callerId.Value, exchange, ct);
                break;
            case "download-recovery":
                await DownloadRecovery(mfaService, callerId.Value, exchange, ct);
                break;
            default:
                exchange.Out.Body = Error("invalid_operation", $"Unknown MFA operation: {operation}");
                break;
        }

        // For self-service, audit events carry the caller id explicitly.
        if (operation == "download-recovery" && exchange.Out!.Body is byte[])
        {
            // Download-recovery body is plaintext bytes (the file payload) — emit the
            // dedicated audit event so the audit sink categorizes it under Mfa rather
            // than the generic MfaSelfService:* fallback.
            exchange.Properties["identity-event-type"] = redb.Identity.Contracts.Routes.IdentityAuditEventIds.MfaRecoveryCodesDownloaded;
            exchange.Properties["identity-event-data"] = new { UserId = callerId.Value };
        }
        else if (exchange.Out!.Body is Dictionary<string, object?> dict && !dict.ContainsKey("error"))
        {
            exchange.Properties["identity-event-type"] = $"MfaSelfService:{operation}";
            exchange.Properties["identity-event-data"] = new { UserId = callerId.Value, Operation = operation };
        }
    }

    private static string? GetString(IDictionary<string, object?>? body, string key)
    {
        if (body is null) return null;
        return body.TryGetValue(key, out var v) ? v?.ToString() : null;
    }

    private static async Task Status(MfaService mfaService, long userId, IExchange exchange, CancellationToken ct)
    {
        var status = await mfaService.GetStatusAsync(userId, ct);
        exchange.Out!.Body = new Dictionary<string, object?>
        {
            ["enabled"] = status.Enabled,
            ["methods"] = status.Methods,
            ["recovery_codes_remaining"] = status.RecoveryCodesRemaining
        };
    }

    private static async Task Setup(
        MfaService mfaService, long userId, IDictionary<string, object?>? body,
        IExchange exchange, CancellationToken ct)
    {
        var method = GetString(body, "method") ?? "totp";
        var username = GetString(body, "username") ?? "";
        var destination = GetString(body, "destination");

        var result = await mfaService.SetupAsync(userId, method, username, destination, ct);

        if (result.Extra is not null && result.Extra.TryGetValue("error", out var err) && err is string errStr)
        {
            exchange.Out!.Body = Error("invalid_request", errStr);
            return;
        }

        var response = new Dictionary<string, object?>
        {
            ["method"] = result.MethodId,
            ["secret_base32"] = result.SecretBase32,
            ["qr_uri"] = result.QrUri,
            ["setup_token"] = result.SetupToken
        };
        if (result.Extra is not null)
        {
            foreach (var (k, v) in result.Extra)
                response[k] = v;
        }

        exchange.Out!.Body = response;
    }

    private static async Task Confirm(
        MfaService mfaService, long userId, IDictionary<string, object?>? body,
        IExchange exchange, CancellationToken ct)
    {
        var method = GetString(body, "method") ?? "totp";
        var code = GetString(body, "code");
        var setupToken = GetString(body, "setup_token");
        var protectedState = GetString(body, "mfa_state");

        if (string.IsNullOrEmpty(code))
        {
            exchange.Out!.Body = Error("invalid_request", "Missing code");
            return;
        }
        if (string.IsNullOrEmpty(setupToken))
        {
            exchange.Out!.Body = Error("invalid_request", "Missing setup_token");
            return;
        }

        Models.MfaState? state = null;
        if (!string.IsNullOrEmpty(protectedState))
            state = mfaService.UnprotectState(protectedState);

        var recoveryCodes = await mfaService.ConfirmSetupAsync(userId, method, code, setupToken, state, ct);
        if (recoveryCodes is null)
        {
            exchange.Out!.Body = Error("invalid_code", "Invalid verification code");
            return;
        }

        exchange.Out!.Body = new Dictionary<string, object?>
        {
            ["confirmed"] = true,
            ["recovery_codes"] = recoveryCodes
        };
    }

    private static async Task Disable(
        MfaService mfaService, long userId, IDictionary<string, object?>? body,
        IExchange exchange, CancellationToken ct)
    {
        var method = GetString(body, "method") ?? "totp";
        await mfaService.DisableAsync(userId, method, ct);
        exchange.Out!.Body = new Dictionary<string, object?> { ["disabled"] = true };
    }

    private static async Task RegenerateRecovery(
        MfaService mfaService, long userId, IExchange exchange, CancellationToken ct)
    {
        var codes = await mfaService.RegenerateRecoveryCodesAsync(userId, ct);
        if (codes is null)
        {
            exchange.Out!.Body = Error("mfa_not_enabled", "MFA is not enabled for this user");
            return;
        }

        exchange.Out!.Body = new Dictionary<string, object?> { ["recovery_codes"] = codes };
    }

    /// <summary>
    /// MFA backup-codes download UX: regenerates the recovery codes (atomically invalidates
    /// the previous set in the same way as <c>regenerate-recovery</c>) and returns the fresh
    /// codes as a <c>text/plain</c> attachment so the user can save the file. Recovery codes
    /// are stored only as salted hashes — there is no other moment they exist in plaintext
    /// on the server, so download is necessarily destructive (mirrors Google / GitHub /
    /// Auth0 behaviour: every "download backup codes" click invalidates the prior batch).
    /// </summary>
    private static async Task DownloadRecovery(
        MfaService mfaService, long userId, IExchange exchange, CancellationToken ct)
    {
        var codes = await mfaService.RegenerateRecoveryCodesAsync(userId, ct);
        if (codes is null)
        {
            exchange.Out!.Body = Error("mfa_not_enabled", "MFA is not enabled for this user");
            return;
        }

        // Plain-text body: one code per line + a header banner identifying the issuer and
        // the timestamp so a downloaded file is self-describing if the user revisits it years
        // later. UTF-8 BOM not added — plain ASCII codes only, BOM would confuse some editors.
        var now = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd HH:mm:ss 'UTC'");
        var sb = new System.Text.StringBuilder();
        sb.Append("# redb.Identity MFA recovery codes\r\n");
        sb.Append("# Generated: ").Append(now).Append("\r\n");
        sb.Append("# Each code may be used exactly once. Store this file in a secure location.\r\n");
        sb.Append("# Downloading a new batch invalidates this one.\r\n");
        sb.Append("\r\n");
        foreach (var code in codes)
            sb.Append(code).Append("\r\n");

        exchange.Out!.Body = System.Text.Encoding.UTF8.GetBytes(sb.ToString());
        exchange.Out!.Headers["Content-Type"] = "text/plain; charset=utf-8";
        exchange.Out!.Headers["redbHttp.ResponseContentType"] = "text/plain; charset=utf-8";
        exchange.Out!.Headers["Content-Disposition"] =
            "attachment; filename=\"redb-recovery-codes.txt\"";
        // Disable any cache between client and server — the file contains plaintext
        // recovery secrets, never cache it anywhere.
        exchange.Out!.Headers["Cache-Control"] = "no-store, max-age=0";
        exchange.Out!.Headers["Pragma"] = "no-cache";
    }

    private static Dictionary<string, object?> Error(string error, string description) =>
        new()
        {
            ["error"] = error,
            ["error_description"] = description
        };
}
