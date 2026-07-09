using System.Text.Json;

namespace redb.Identity.Client;

public partial interface IIdentityClient
{
    // ── Status ──
    /// <summary>Get MFA enrolment status for a user (admin).</summary>
    Task<JsonElement> GetUserMfaStatusAsync(long userId, CancellationToken ct = default);

    // ── TOTP ──
    /// <summary>Begin TOTP setup for a user (admin). Returns QR/secret.</summary>
    Task<JsonElement> SetupUserTotpAsync(long userId, string username, CancellationToken ct = default);
    /// <summary>Confirm TOTP setup with a verification code (admin).</summary>
    Task<JsonElement> ConfirmUserTotpAsync(long userId, string code, CancellationToken ct = default);
    /// <summary>Disable TOTP for a user (admin).</summary>
    Task<JsonElement> DisableUserTotpAsync(long userId, CancellationToken ct = default);

    // ── Recovery codes ──
    /// <summary>Regenerate recovery codes for a user (admin). Returns plain codes ONCE.</summary>
    Task<JsonElement> RegenerateUserRecoveryCodesAsync(long userId, CancellationToken ct = default);

    // ── SMS ──
    /// <summary>Begin SMS OTP setup for a user (admin).</summary>
    Task<JsonElement> SetupUserSmsAsync(long userId, string username, string destination, CancellationToken ct = default);
    /// <summary>Confirm SMS OTP setup (admin).</summary>
    Task<JsonElement> ConfirmUserSmsAsync(long userId, string code, string? mfaState = null, CancellationToken ct = default);
    /// <summary>Disable SMS OTP for a user (admin).</summary>
    Task<JsonElement> DisableUserSmsAsync(long userId, CancellationToken ct = default);

    // ── Email ──
    /// <summary>Begin Email OTP setup for a user (admin).</summary>
    Task<JsonElement> SetupUserEmailAsync(long userId, string username, string destination, CancellationToken ct = default);
    /// <summary>Confirm Email OTP setup (admin).</summary>
    Task<JsonElement> ConfirmUserEmailAsync(long userId, string code, string? mfaState = null, CancellationToken ct = default);
    /// <summary>Disable Email OTP for a user (admin).</summary>
    Task<JsonElement> DisableUserEmailAsync(long userId, CancellationToken ct = default);
}

public sealed partial class IdentityClient
{
    private const string MfaAdminBase = "/api/v1/identity/mfa";

    public async Task<JsonElement> GetUserMfaStatusAsync(long userId, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{MfaAdminBase}/status/{userId}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    // TOTP
    public async Task<JsonElement> SetupUserTotpAsync(long userId, string username, CancellationToken ct = default)
    {
        var body = new { userId, username };
        using var resp = await _http.PostAsJsonAsync($"{MfaAdminBase}/totp/setup", body, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> ConfirmUserTotpAsync(long userId, string code, CancellationToken ct = default)
    {
        var body = new { userId, code };
        using var resp = await _http.PostAsJsonAsync($"{MfaAdminBase}/totp/confirm", body, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> DisableUserTotpAsync(long userId, CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{MfaAdminBase}/totp/{userId}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    // Recovery codes
    public async Task<JsonElement> RegenerateUserRecoveryCodesAsync(long userId, CancellationToken ct = default)
    {
        var body = new { userId };
        using var resp = await _http.PostAsJsonAsync($"{MfaAdminBase}/recovery-codes/regenerate", body, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    // SMS
    public async Task<JsonElement> SetupUserSmsAsync(long userId, string username, string destination, CancellationToken ct = default)
    {
        var body = new { userId, username, destination };
        using var resp = await _http.PostAsJsonAsync($"{MfaAdminBase}/sms/setup", body, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> ConfirmUserSmsAsync(long userId, string code, string? mfaState = null, CancellationToken ct = default)
    {
        var body = new { userId, code, mfaState };
        using var resp = await _http.PostAsJsonAsync($"{MfaAdminBase}/sms/confirm", body, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> DisableUserSmsAsync(long userId, CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{MfaAdminBase}/sms/{userId}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    // Email
    public async Task<JsonElement> SetupUserEmailAsync(long userId, string username, string destination, CancellationToken ct = default)
    {
        var body = new { userId, username, destination };
        using var resp = await _http.PostAsJsonAsync($"{MfaAdminBase}/email/setup", body, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> ConfirmUserEmailAsync(long userId, string code, string? mfaState = null, CancellationToken ct = default)
    {
        var body = new { userId, code, mfaState };
        using var resp = await _http.PostAsJsonAsync($"{MfaAdminBase}/email/confirm", body, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> DisableUserEmailAsync(long userId, CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{MfaAdminBase}/email/{userId}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }
}
