using System.Text.Json;
using redb.Identity.Contracts.Consents;
using redb.Identity.Contracts.Users;

namespace redb.Identity.Client;

public partial interface IIdentityClient
{
    // ── /me — profile ──
    /// <summary>Get the caller's own profile.</summary>
    Task<JsonElement> GetMyProfileAsync(CancellationToken ct = default);
    /// <summary>Update the caller's own profile (PUT).</summary>
    Task<JsonElement> UpdateMyProfileAsync(MeUpdateProfileRequest request, CancellationToken ct = default);

    // ── /me/password ──
    /// <summary>Change the caller's password. All sessions are revoked on success.</summary>
    Task<JsonElement> ChangeMyPasswordAsync(MeChangePasswordRequest request, CancellationToken ct = default);

    // ── /me/sessions ──
    /// <summary>List the caller's own active sessions.</summary>
    Task<JsonElement> ListMySessionsAsync(CancellationToken ct = default);
    /// <summary>Revoke the session bound to the caller's current access token.</summary>
    Task<JsonElement> RevokeMyCurrentSessionAsync(CancellationToken ct = default);
    /// <summary>Revoke one of the caller's own sessions by id.</summary>
    Task<JsonElement> RevokeMySessionAsync(long sessionId, CancellationToken ct = default);
    /// <summary>Revoke all of the caller's sessions except the current one (identified by the sid claim).</summary>
    Task<JsonElement> RevokeMyOtherSessionsAsync(CancellationToken ct = default);

    // ── /me/mfa ──
    /// <summary>Get caller's MFA enrolment status.</summary>
    Task<JsonElement> GetMyMfaStatusAsync(CancellationToken ct = default);
    /// <summary>Begin enrolment of an MFA method for the caller.</summary>
    Task<JsonElement> SetupMyMfaAsync(IDictionary<string, object?> body, CancellationToken ct = default);
    /// <summary>Confirm a pending MFA enrolment with the OTP code.</summary>
    Task<JsonElement> ConfirmMyMfaAsync(IDictionary<string, object?> body, CancellationToken ct = default);
    /// <summary>Disable a single MFA method registered to the caller.</summary>
    Task<JsonElement> DisableMyMfaMethodAsync(string method, CancellationToken ct = default);
    /// <summary>Regenerate the caller's recovery codes (invalidates previous codes).</summary>
    Task<JsonElement> RegenerateMyRecoveryCodesAsync(CancellationToken ct = default);
    /// <summary>Download the caller's recovery codes as text/plain (also regenerates).</summary>
    Task<HttpResponseMessage> DownloadMyRecoveryCodesAsync(CancellationToken ct = default);

    // ── /me/webauthn ──
    /// <summary>Get caller's WebAuthn enrolment status.</summary>
    Task<JsonElement> GetMyWebAuthnStatusAsync(CancellationToken ct = default);
    /// <summary>Begin a WebAuthn registration ceremony.</summary>
    Task<JsonElement> BeginMyWebAuthnRegistrationAsync(IDictionary<string, object?> body, CancellationToken ct = default);
    /// <summary>Complete WebAuthn registration with browser attestation.</summary>
    Task<JsonElement> CompleteMyWebAuthnRegistrationAsync(IDictionary<string, object?> body, CancellationToken ct = default);
    /// <summary>List the caller's registered WebAuthn credentials.</summary>
    Task<JsonElement> ListMyWebAuthnCredentialsAsync(CancellationToken ct = default);
    /// <summary>Rename a single WebAuthn credential.</summary>
    Task<JsonElement> RenameMyWebAuthnCredentialAsync(string key, IDictionary<string, object?> body, CancellationToken ct = default);
    /// <summary>Delete a single WebAuthn credential.</summary>
    Task<JsonElement> DeleteMyWebAuthnCredentialAsync(string key, CancellationToken ct = default);

    // ── /me/consents ──
    /// <summary>List the caller's valid permanent consent grants.</summary>
    Task<JsonElement> ListMyConsentsAsync(CancellationToken ct = default);
    /// <summary>Revoke the caller's permanent consent grant for a single client.</summary>
    Task<JsonElement> RevokeMyConsentAsync(string clientId, CancellationToken ct = default);
}

public sealed partial class IdentityClient
{
    private const string MeBase = "/api/v1/identity/me";

    // ── Profile ──
    public async Task<JsonElement> GetMyProfileAsync(CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync(MeBase, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> UpdateMyProfileAsync(MeUpdateProfileRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PutAsJsonAsync(MeBase, request, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    // ── Password ──
    public async Task<JsonElement> ChangeMyPasswordAsync(MeChangePasswordRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PutAsJsonAsync($"{MeBase}/password", request, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    // ── Sessions ──
    public async Task<JsonElement> ListMySessionsAsync(CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{MeBase}/sessions", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> RevokeMyCurrentSessionAsync(CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{MeBase}/sessions/current", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> RevokeMySessionAsync(long sessionId, CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{MeBase}/sessions/{sessionId}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> RevokeMyOtherSessionsAsync(CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{MeBase}/sessions/others", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    // ── MFA (self) ──
    public async Task<JsonElement> GetMyMfaStatusAsync(CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{MeBase}/mfa", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> SetupMyMfaAsync(IDictionary<string, object?> body, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{MeBase}/mfa/setup", body, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> ConfirmMyMfaAsync(IDictionary<string, object?> body, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{MeBase}/mfa/confirm", body, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> DisableMyMfaMethodAsync(string method, CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{MeBase}/mfa/{Uri.EscapeDataString(method)}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> RegenerateMyRecoveryCodesAsync(CancellationToken ct = default)
    {
        using var resp = await _http.PostAsync($"{MeBase}/mfa/recovery-codes", content: null, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    /// <remarks>
    /// Returns the raw <see cref="HttpResponseMessage"/> so the caller can stream the
    /// text/plain attachment to disk. Caller is responsible for disposal.
    /// </remarks>
    public async Task<HttpResponseMessage> DownloadMyRecoveryCodesAsync(CancellationToken ct = default)
    {
        var resp = await _http.GetAsync($"{MeBase}/mfa/recovery-codes/download", HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        await resp.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
        return resp;
    }

    // ── WebAuthn (self) ──
    public async Task<JsonElement> GetMyWebAuthnStatusAsync(CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{MeBase}/webauthn", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> BeginMyWebAuthnRegistrationAsync(IDictionary<string, object?> body, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{MeBase}/webauthn/register/begin", body, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> CompleteMyWebAuthnRegistrationAsync(IDictionary<string, object?> body, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{MeBase}/webauthn/register/complete", body, _json, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> ListMyWebAuthnCredentialsAsync(CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{MeBase}/webauthn/credentials", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> RenameMyWebAuthnCredentialAsync(string key, IDictionary<string, object?> body, CancellationToken ct = default)
    {
        var url = $"{MeBase}/webauthn/credentials/{Uri.EscapeDataString(key)}";
        using var req = new HttpRequestMessage(HttpMethod.Patch, url) { Content = JsonContent.Create(body, options: _json) };
        using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> DeleteMyWebAuthnCredentialAsync(string key, CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{MeBase}/webauthn/credentials/{Uri.EscapeDataString(key)}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    // ── Consents (self) ──
    public async Task<JsonElement> ListMyConsentsAsync(CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync($"{MeBase}/consents", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> RevokeMyConsentAsync(string clientId, CancellationToken ct = default)
    {
        using var resp = await _http.DeleteAsync($"{MeBase}/consents/{Uri.EscapeDataString(clientId)}", ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Grant the caller's permanent consent for an application. Used by native consent UIs
    /// (e.g. the BFF Razor page) after the user approves a <c>consent_required</c> dialog.
    /// The user id is taken from the access-token subject; the request body must not include one.
    /// </summary>
    public async Task<JsonElement> GrantMyConsentAsync(string clientId, IEnumerable<string> scopes, CancellationToken ct = default)
    {
        var body = new GrantMyConsentRequest { ClientId = clientId, Scopes = scopes.ToArray() };
        using var req = new HttpRequestMessage(HttpMethod.Post, $"{MeBase}/consents")
        {
            Content = JsonContent.Create(body, options: _json)
        };
        using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        return await resp.ReadJsonAsync<JsonElement>(ct).ConfigureAwait(false);
    }
}
