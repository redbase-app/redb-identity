using System.Text.Json;
using redb.Identity.Contracts.Users;

namespace redb.Identity.Client;

public partial interface IIdentityClient
{
    // ── /me/verify-email & /account/verify-email \u2014 N4-6 e-mail verification ──

    /// <summary>
    /// Initiates the e-mail-verification flow for the authenticated caller. Issues a
    /// single-use verification token bound to the caller's current e-mail address and
    /// delivers it via the server's configured e-mail channel. Requires Bearer auth
    /// (<c>identity:manage</c> or <c>identity:account</c>) and that the supplied
    /// <see cref="EmailVerifySendRequest.CallerVerifyUrl"/> is whitelisted on the
    /// client's <c>EmailVerifyUris</c>.
    /// </summary>
    Task<EmailVerifySendResponse> VerifyEmailSendAsync(EmailVerifySendRequest request, CancellationToken ct = default);

    /// <summary>
    /// Completes the e-mail-verification flow by verifying + atomically consuming the
    /// verification token issued earlier (via e-mail) and flipping
    /// <c>UserProps.EmailVerified</c> to <c>true</c> when the bound e-mail still
    /// matches the user's current address (double-change race protection). All failure
    /// modes return a generic <c>invalid_token</c> response; granular reason is recorded
    /// only in audit logs. This call does NOT require any prior authentication.
    /// </summary>
    Task<EmailVerifyConfirmResponse> VerifyEmailConfirmAsync(EmailVerifyConfirmRequest request, CancellationToken ct = default);
}

public sealed partial class IdentityClient
{
    private const string MeVerifyEmailBase = "/api/v1/identity/me/verify-email";
    private const string AccountVerifyEmailBase = "/api/v1/identity/account/verify-email";

    public async Task<EmailVerifySendResponse> VerifyEmailSendAsync(EmailVerifySendRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{MeVerifyEmailBase}/send", request, _json, ct).ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();
        return await resp.ReadJsonAsync<EmailVerifySendResponse>(ct).ConfigureAwait(false)
               ?? new EmailVerifySendResponse { Success = false };
    }

    public async Task<EmailVerifyConfirmResponse> VerifyEmailConfirmAsync(EmailVerifyConfirmRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{AccountVerifyEmailBase}/confirm", request, _json, ct).ConfigureAwait(false);
        // Mirror ResetPasswordAsync: any non-2xx is collapsed into a generic invalid_token
        // envelope so callers cannot distinguish "wrong jti" from "expired" from "consumed".
        if (!resp.IsSuccessStatusCode)
        {
            return new EmailVerifyConfirmResponse
            {
                Success = false,
                Error = "invalid_token",
                ErrorDescription = "The verification token is invalid or has expired.",
            };
        }
        return await resp.ReadJsonAsync<EmailVerifyConfirmResponse>(ct).ConfigureAwait(false)
               ?? new EmailVerifyConfirmResponse { Success = false, Error = "invalid_response" };
    }
}
