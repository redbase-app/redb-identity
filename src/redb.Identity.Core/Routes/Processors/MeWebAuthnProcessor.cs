using System.Text.Json;
using Fido2NetLib;
using Microsoft.Extensions.DependencyInjection;
using redb.Core;
using redb.Identity.Contracts.Routes;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// MFA-3: self-service WebAuthn management backing <c>/me/webauthn/*</c>. Operations:
/// <list type="bullet">
///   <item><description><c>status</c> \u2014 list whether WebAuthn is enabled (any registered credentials).</description></item>
///   <item><description><c>register-begin</c> \u2014 issue <c>CredentialCreateOptions</c> + <c>setup_token</c>.</description></item>
///   <item><description><c>register-complete</c> \u2014 verify attestation, persist credential, return recovery codes (first method only).</description></item>
///   <item><description><c>credentials</c> \u2014 list all credentials of the caller.</description></item>
///   <item><description><c>credential-rename</c> \u2014 change the friendly label.</description></item>
///   <item><description><c>credential-delete</c> \u2014 remove a credential by key.</description></item>
/// </list>
/// <para>
/// Caller user id is always derived from <c>identity:management-subject</c> \u2014 never from
/// the request body \u2014 mirroring <see cref="MeMfaProcessor"/>.
/// </para>
/// </summary>
internal sealed class MeWebAuthnProcessor : IProcessor
{
    private readonly IServiceProvider _sp;
    private static readonly JsonSerializerOptions s_json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    public MeWebAuthnProcessor(IServiceProvider sp) => _sp = sp;

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
        var mfa = scope.ServiceProvider.GetRequiredService<MfaService>();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var body = exchange.In.Body as IDictionary<string, object?>;

        switch (operation)
        {
            case "status":
                await Status(mfa, callerId.Value, exchange, ct);
                break;
            case "register-begin":
                await RegisterBegin(mfa, redb, callerId.Value, body, exchange, ct);
                break;
            case "register-complete":
                await RegisterComplete(mfa, redb, callerId.Value, body, exchange, ct);
                break;
            case "credentials":
                await ListCredentials(mfa, callerId.Value, exchange, ct);
                break;
            case "credential-rename":
                await Rename(mfa, callerId.Value, body, exchange, ct);
                break;
            case "credential-delete":
                await Delete(mfa, callerId.Value, body, exchange, ct);
                break;
            default:
                exchange.Out.Body = Error("invalid_operation", $"Unknown WebAuthn operation: {operation}");
                break;
        }

        if (exchange.Out!.Body is Dictionary<string, object?> dict && !dict.ContainsKey("error"))
        {
            exchange.Properties["identity-event-type"] = $"MfaSelfService:webauthn:{operation}";
            exchange.Properties["identity-event-data"] = new { UserId = callerId.Value, Operation = operation };
        }
    }

    private static async Task Status(MfaService mfa, long userId, IExchange exchange, CancellationToken ct)
    {
        var creds = await mfa.ListWebAuthnCredentialsAsync(userId, ct);
        exchange.Out!.Body = new Dictionary<string, object?>
        {
            ["enabled"] = creds.Count > 0,
            ["credentials_count"] = creds.Count,
        };
    }

    private static async Task RegisterBegin(
        MfaService mfa, IRedbService redb, long userId,
        IDictionary<string, object?>? body, IExchange exchange, CancellationToken ct)
    {
        var username = GetString(body, "username") ?? "";
        var displayName = GetString(body, "display_name") ?? username;

        // Forward to the orchestrator. The challenge + serialized options are bound into the
        // returned setup_token and round-tripped to the client opaque-style.
        var (options, setupToken) = await mfa.BeginWebAuthnRegistrationAsync(userId, username, displayName, ct);

        exchange.Out!.Body = new Dictionary<string, object?>
        {
            ["options"] = JsonSerializer.SerializeToElement(options, s_json),
            ["setup_token"] = setupToken,
        };
    }

    private static async Task RegisterComplete(
        MfaService mfa, IRedbService redb, long userId,
        IDictionary<string, object?>? body, IExchange exchange, CancellationToken ct)
    {
        var setupToken = GetString(body, "setup_token");
        var attestationRaw = body is not null && body.TryGetValue("attestation", out var att) ? att : null;
        var displayName = GetString(body, "display_name");

        if (string.IsNullOrEmpty(setupToken) || attestationRaw is null)
        {
            exchange.Out!.Body = Error("invalid_request", "Missing setup_token or attestation");
            return;
        }

        AuthenticatorAttestationRawResponse? attestation;
        try
        {
            var json = JsonSerializer.Serialize(attestationRaw, s_json);
            attestation = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(json, s_json);
        }
        catch (JsonException ex)
        {
            exchange.Out!.Body = Error("invalid_request", $"Malformed attestation: {ex.Message}");
            return;
        }
        if (attestation is null)
        {
            exchange.Out!.Body = Error("invalid_request", "attestation could not be parsed");
            return;
        }

        // Atomic complete: SELECT ... FOR UPDATE on user's MFA props row, then run the full
        // verification + persistence inside the same TX. Mirrors MfaVerifyProcessor.
        var mfaObjId = await mfa.GetMfaObjectIdAsync(userId, ct);

        (bool ok, string[]? recovery, string? key, string? error) result;
        await using (var tx = await redb.Context.BeginTransactionAsync())
        {
            if (mfaObjId != 0)
                await redb.LockForUpdateAsync(mfaObjId);
            result = await mfa.CompleteWebAuthnRegistrationAsync(
                userId, attestation, setupToken!, displayName, ct);
            await tx.CommitAsync();
        }

        if (!result.ok)
        {
            exchange.Out!.Body = Error(result.error ?? "register_failed", "WebAuthn registration failed");
            return;
        }

        exchange.Out!.Body = new Dictionary<string, object?>
        {
            ["registered"] = true,
            ["credential_key"] = result.key,
            ["recovery_codes"] = result.recovery ?? Array.Empty<string>(),
        };
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.MfaWebAuthnRegistered;
        exchange.Properties["identity-event-data"] = new
        {
            UserId = userId,
            CredentialKey = result.key,
        };
    }

    private static async Task ListCredentials(MfaService mfa, long userId, IExchange exchange, CancellationToken ct)
    {
        var creds = await mfa.ListWebAuthnCredentialsAsync(userId, ct);
        exchange.Out!.Body = new Dictionary<string, object?>
        {
            ["credentials"] = creds.Select(c => new Dictionary<string, object?>
            {
                ["key"] = c.Key,
                ["display_name"] = c.DisplayName,
                ["aaguid"] = c.Aaguid,
                ["registered_at"] = c.RegisteredAt,
                ["last_used_at"] = c.LastUsedAt,
                ["user_verified"] = c.UserVerified,
                ["backup_eligible"] = c.BackupEligible,
                ["backup_state"] = c.BackupState,
            }).ToList(),
        };
    }

    private static async Task Rename(MfaService mfa, long userId,
        IDictionary<string, object?>? body, IExchange exchange, CancellationToken ct)
    {
        var key = GetString(body, "key") ?? GetString(body, "credential_key");
        var name = GetString(body, "display_name");
        if (string.IsNullOrEmpty(key))
        {
            exchange.Out!.Body = Error("invalid_request", "Missing key");
            return;
        }
        var ok = await mfa.RenameWebAuthnCredentialAsync(userId, key!, name, ct);
        if (!ok)
        {
            exchange.Out!.Body = Error("not_found", "Credential not found");
            return;
        }
        exchange.Out!.Body = new Dictionary<string, object?> { ["renamed"] = true };
    }

    private static async Task Delete(MfaService mfa, long userId,
        IDictionary<string, object?>? body, IExchange exchange, CancellationToken ct)
    {
        var key = GetString(body, "key") ?? GetString(body, "credential_key");
        if (string.IsNullOrEmpty(key))
        {
            exchange.Out!.Body = Error("invalid_request", "Missing key");
            return;
        }
        var ok = await mfa.DeleteWebAuthnCredentialAsync(userId, key!, ct);
        if (!ok)
        {
            exchange.Out!.Body = Error("not_found", "Credential not found");
            return;
        }
        exchange.Out!.Body = new Dictionary<string, object?> { ["deleted"] = true };
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.MfaWebAuthnRevoked;
        exchange.Properties["identity-event-data"] = new
        {
            UserId = userId,
            CredentialKey = key,
        };
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
