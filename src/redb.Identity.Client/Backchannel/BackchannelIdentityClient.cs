using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using redb.Identity.Contracts.Sessions;
using redb.Identity.Contracts.Users;

namespace redb.Identity.Client.Backchannel;

/// <summary>
/// Default <see cref="IBackchannelIdentityClient"/> implementation. Owns a typed
/// <see cref="HttpClient"/> registered via
/// <see cref="BackchannelServiceCollectionExtensions.AddBackchannelIdentityClient"/>.
/// </summary>
public sealed class BackchannelIdentityClient : IBackchannelIdentityClient
{
    private const string BasePath = "/api/v1/identity/revoked-sids";
    private const string PasswordBasePath = "/api/v1/identity/password";
    private const string AccountVerifyEmailBasePath = "/api/v1/identity/account/verify-email";
    private const string AccountChangeEmailBasePath = "/api/v1/identity/account/change-email";
    private const string AccountRegisterBasePath = "/api/v1/identity/account/register";
    private readonly HttpClient _http;
    private readonly JsonSerializerOptions _json;

    public BackchannelIdentityClient(HttpClient http, IOptions<BackchannelIdentityClientOptions> opts)
    {
        _http = http;
        var o = opts.Value;
        _http.BaseAddress ??= o.BaseUrl;
        _json = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            PropertyNameCaseInsensitive = true,
            Converters = { new JsonStringEnumConverter() }
        };
    }

    public async Task<RevokedSidEntry> AddRevokedSidAsync(
        string? sid, string? sub, string? clientId,
        DateTimeOffset? expiresAt = null,
        CancellationToken ct = default)
    {
        var request = new RevokedSidsAddRequest
        {
            Sid = sid,
            Sub = sub,
            ClientId = clientId,
            ExpiresAt = expiresAt
        };
        using var resp = await _http.PostAsJsonAsync(BasePath, request, _json, ct).ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();
        return (await resp.Content.ReadFromJsonAsync<RevokedSidEntry>(_json, ct).ConfigureAwait(false))!;
    }

    public async Task<RevokedSidsSinceResponse> GetRevokedSidsSinceAsync(
        DateTimeOffset? cursor = null,
        CancellationToken ct = default)
    {
        var url = cursor.HasValue
            ? $"{BasePath}/since?cursor={Uri.EscapeDataString(cursor.Value.ToString("O"))}"
            : $"{BasePath}/since";
        using var resp = await _http.GetAsync(url, ct).ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();
        return (await resp.Content.ReadFromJsonAsync<RevokedSidsSinceResponse>(_json, ct).ConfigureAwait(false))!;
    }

    public async Task<PasswordForgotResponse> ForgotPasswordAsync(
        PasswordForgotRequest request,
        CancellationToken ct = default)
    {
        // Anonymous endpoint on the host — the management bearer the typed client carries
        // is ignored by the anonymous-prefix bypass. Any non-2xx is treated as success at
        // this layer to preserve the anti-enumeration contract end-to-end.
        using var resp = await _http.PostAsJsonAsync($"{PasswordBasePath}/forgot", request, _json, ct).ConfigureAwait(false);
        return new PasswordForgotResponse { Success = true };
    }

    public async Task<PasswordResetResponse> ResetPasswordAsync(
        PasswordResetRequest request,
        CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{PasswordBasePath}/reset", request, _json, ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
        {
            return new PasswordResetResponse
            {
                Success = false,
                Error = "invalid_token",
                ErrorDescription = "The reset token is invalid or has expired."
            };
        }
        return (await resp.Content.ReadFromJsonAsync<PasswordResetResponse>(_json, ct).ConfigureAwait(false))
               ?? new PasswordResetResponse { Success = false, Error = "empty_response" };
    }

    public async Task<EmailVerifyConfirmResponse> VerifyEmailConfirmAsync(
        EmailVerifyConfirmRequest request,
        CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{AccountVerifyEmailBasePath}/confirm", request, _json, ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
        {
            return new EmailVerifyConfirmResponse
            {
                Success = false,
                Error = "invalid_token",
                ErrorDescription = "The verification token is invalid or has expired."
            };
        }
        return (await resp.Content.ReadFromJsonAsync<EmailVerifyConfirmResponse>(_json, ct).ConfigureAwait(false))
               ?? new EmailVerifyConfirmResponse { Success = false, Error = "empty_response" };
    }

    public async Task<ChangeEmailConfirmResponse> ChangeEmailConfirmAsync(
        ChangeEmailConfirmRequest request,
        CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{AccountChangeEmailBasePath}/confirm", request, _json, ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
        {
            return new ChangeEmailConfirmResponse
            {
                Success = false,
                Error = "invalid_token",
                ErrorDescription = "The confirmation token is invalid or has expired."
            };
        }
        return (await resp.Content.ReadFromJsonAsync<ChangeEmailConfirmResponse>(_json, ct).ConfigureAwait(false))
               ?? new ChangeEmailConfirmResponse { Success = false, Error = "empty_response" };
    }

    public async Task<RegisterAccountResponse> RegisterAccountAsync(
        RegisterAccountRequest request,
        CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync(AccountRegisterBasePath, request, _json, ct).ConfigureAwait(false);
        if (resp.IsSuccessStatusCode)
        {
            return (await resp.Content.ReadFromJsonAsync<RegisterAccountResponse>(_json, ct).ConfigureAwait(false))
                   ?? new RegisterAccountResponse { Success = false, Error = "empty_response" };
        }

        // Structured failure: the host always returns a typed body on rejections; surface
        // the body verbatim so the BFF can render the actionable error to the user.
        try
        {
            var body = await resp.Content.ReadFromJsonAsync<RegisterAccountResponse>(_json, ct).ConfigureAwait(false);
            if (body is not null && !string.IsNullOrEmpty(body.Error))
                return body;
        }
        catch
        {
            // Fall through to canonical fallback below.
        }

        var fallbackError = resp.StatusCode switch
        {
            System.Net.HttpStatusCode.NotFound or System.Net.HttpStatusCode.Forbidden => "registration_disabled",
            System.Net.HttpStatusCode.Conflict => "duplicate",
            System.Net.HttpStatusCode.BadRequest => "validation_error",
            _ => "registration_failed",
        };
        return new RegisterAccountResponse
        {
            Success = false,
            Error = fallbackError,
            ErrorDescription = $"Account registration failed with HTTP status {(int)resp.StatusCode}.",
        };
    }
}
