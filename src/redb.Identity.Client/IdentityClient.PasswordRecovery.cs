using System.Text.Json;
using redb.Identity.Contracts.Users;

namespace redb.Identity.Client;

public partial interface IIdentityClient
{
    // ── /password — N-4 password recovery (anonymous) ──
    /// <summary>
    /// Initiates the password-recovery flow for the supplied e-mail. Anti-enumeration:
    /// always returns <c>{ success = true }</c>, even when the e-mail does not match a
    /// known user, the client is unknown, or the supplied <c>callerResetUrl</c> is not
    /// whitelisted on the client. This call does NOT require any prior authentication.
    /// </summary>
    Task<PasswordForgotResponse> ForgotPasswordAsync(PasswordForgotRequest request, CancellationToken ct = default);

    /// <summary>
    /// Completes the password-recovery flow by verifying + atomically consuming the
    /// reset token issued earlier (via e-mail) and setting the new password. Revokes
    /// every active session on success. All failure modes return a generic
    /// <c>invalid_token</c> response with no granular reason \u2014 the actual cause is
    /// recorded only in audit logs. This call does NOT require any prior authentication.
    /// </summary>
    Task<PasswordResetResponse> ResetPasswordAsync(PasswordResetRequest request, CancellationToken ct = default);
}

public sealed partial class IdentityClient
{
    private const string PasswordBase = "/api/v1/identity/password";

    public async Task<PasswordForgotResponse> ForgotPasswordAsync(PasswordForgotRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{PasswordBase}/forgot", request, _json, ct).ConfigureAwait(false);
        // Anti-enumeration: facade always returns 200 success regardless of outcome,
        // so we do not interpret the status as a signal here.
        return await resp.ReadJsonAsync<PasswordForgotResponse>(ct).ConfigureAwait(false)
               ?? new PasswordForgotResponse();
    }

    public async Task<PasswordResetResponse> ResetPasswordAsync(PasswordResetRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{PasswordBase}/reset", request, _json, ct).ConfigureAwait(false);
        // Treat any non-2xx as a generic failure; the server already deliberately collapses
        // every reset-failure cause into "invalid_token" to deny attackers useful signal.
        if (!resp.IsSuccessStatusCode)
        {
            return new PasswordResetResponse
            {
                Success = false,
                Error = "invalid_token",
                ErrorDescription = "The reset token is invalid or has expired.",
            };
        }
        return await resp.ReadJsonAsync<PasswordResetResponse>(ct).ConfigureAwait(false)
               ?? new PasswordResetResponse { Success = false, Error = "invalid_response" };
    }
}
