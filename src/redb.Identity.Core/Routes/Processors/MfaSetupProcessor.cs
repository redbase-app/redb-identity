using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// Core route processor for MFA management operations (setup, confirm, disable, status, regenerate).
/// Dispatches by <c>operation</c> header, same pattern as <see cref="UserManagementProcessor"/>.
/// </summary>
internal sealed class MfaSetupProcessor : IProcessor
{
    private readonly IServiceProvider _sp;

    public MfaSetupProcessor(IServiceProvider sp) => _sp = sp;

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var operation = exchange.In.GetHeader<string>("operation")
            ?? throw new InvalidOperationException("Missing 'operation' header");

        exchange.Out = new Message();

        using var scope = _sp.CreateScope();
        var mfaService = scope.ServiceProvider.GetRequiredService<MfaService>();

        var body = exchange.In.Body as IDictionary<string, object?>;

        switch (operation)
        {
            case "status":
                await Status(mfaService, body, exchange, ct);
                break;
            case "setup":
                await Setup(mfaService, body, exchange, ct);
                break;
            case "confirm":
                await Confirm(mfaService, body, exchange, ct);
                break;
            case "disable":
                await Disable(mfaService, body, exchange, ct);
                break;
            case "regenerate-recovery":
                await RegenerateRecovery(mfaService, body, exchange, ct);
                break;
            default:
                exchange.Out.Body = new Dictionary<string, object?>
                {
                    ["error"] = "invalid_operation",
                    ["error_description"] = $"Unknown MFA operation: {operation}"
                };
                break;
        }
    }

    private static long GetUserId(IDictionary<string, object?>? body)
    {
        if (body is null) return 0;
        if (!body.TryGetValue("userId", out var v) || v is null) return 0;
        return v switch
        {
            long id => id,
            int intId => intId,
            double d => (long)d,
            decimal dec => (long)dec,
            JsonElement je when je.TryGetInt64(out var jid) => jid,
            string s when long.TryParse(s, out var parsed) => parsed,
            _ => 0
        };
    }

    private static string? GetString(IDictionary<string, object?>? body, string key)
    {
        if (body is null) return null;
        return body.TryGetValue(key, out var v) ? v?.ToString() : null;
    }

    private static async Task Status(
        MfaService mfaService, IDictionary<string, object?>? body,
        IExchange exchange, CancellationToken ct)
    {
        var userId = GetUserId(body);
        if (userId <= 0)
        {
            exchange.Out!.Body = Error("invalid_request", "Missing userId");
            return;
        }

        var status = await mfaService.GetStatusAsync(userId, ct);
        exchange.Out!.Body = new Dictionary<string, object?>
        {
            ["enabled"] = status.Enabled,
            ["methods"] = status.Methods,
            ["recovery_codes_remaining"] = status.RecoveryCodesRemaining
        };
    }

    private static async Task Setup(
        MfaService mfaService, IDictionary<string, object?>? body,
        IExchange exchange, CancellationToken ct)
    {
        var userId = GetUserId(body);
        var method = GetString(body, "method") ?? "totp";
        var username = GetString(body, "username") ?? "";
        var destination = GetString(body, "destination");

        if (userId <= 0)
        {
            exchange.Out!.Body = Error("invalid_request", "Missing userId");
            return;
        }

        var result = await mfaService.SetupAsync(userId, method, username, destination, ct);

        // Surface setup error from the method (e.g. invalid phone/email).
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
            // B5: opaque encrypted setup token; client MUST send it back in the confirm call.
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
        MfaService mfaService, IDictionary<string, object?>? body,
        IExchange exchange, CancellationToken ct)
    {
        var userId = GetUserId(body);
        var method = GetString(body, "method") ?? "totp";
        var code = GetString(body, "code");
        var setupToken = GetString(body, "setup_token");
        var protectedState = GetString(body, "mfa_state");

        if (userId <= 0 || string.IsNullOrEmpty(code))
        {
            exchange.Out!.Body = Error("invalid_request", "Missing userId or code");
            return;
        }
        if (string.IsNullOrEmpty(setupToken))
        {
            exchange.Out!.Body = Error("invalid_request", "Missing setup_token");
            return;
        }

        // For SMS/Email confirmation, the OTP code lives inside the encrypted state from CreateChallengeAsync.
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
        MfaService mfaService, IDictionary<string, object?>? body,
        IExchange exchange, CancellationToken ct)
    {
        var userId = GetUserId(body);
        var method = GetString(body, "method") ?? "totp";

        if (userId <= 0)
        {
            exchange.Out!.Body = Error("invalid_request", "Missing userId");
            return;
        }

        await mfaService.DisableAsync(userId, method, ct);
        exchange.Out!.Body = new Dictionary<string, object?>
        {
            ["disabled"] = true
        };
    }

    private static async Task RegenerateRecovery(
        MfaService mfaService, IDictionary<string, object?>? body,
        IExchange exchange, CancellationToken ct)
    {
        var userId = GetUserId(body);
        if (userId <= 0)
        {
            exchange.Out!.Body = Error("invalid_request", "Missing userId");
            return;
        }

        var codes = await mfaService.RegenerateRecoveryCodesAsync(userId, ct);
        if (codes is null)
        {
            exchange.Out!.Body = Error("mfa_not_enabled", "MFA is not enabled for this user");
            return;
        }

        exchange.Out!.Body = new Dictionary<string, object?>
        {
            ["recovery_codes"] = codes
        };
    }

    private static Dictionary<string, object?> Error(string error, string description) =>
        new()
        {
            ["error"] = error,
            ["error_description"] = description
        };
}
