using redb.Identity.Contracts.Users;

namespace redb.Identity.Client;

public partial interface IIdentityClient
{
    // \u2500\u2500 /me/change-email & /account/change-email \u2014 N4-7 strict change-of-e-mail \u2500\u2500

    /// <summary>
    /// Initiates the verify-then-commit change-of-e-mail flow for the authenticated
    /// caller. Issues a single-use confirmation token bound to the user's current
    /// address AND the requested new address, and delivers the confirmation link via
    /// the server's configured e-mail channel \u2014 to the NEW address. The current
    /// address remains the canonical login until the link is clicked. Requires Bearer
    /// auth (<c>identity:manage</c> or <c>identity:account</c>) and that the supplied
    /// <see cref="ChangeEmailRequestRequest.CallerConfirmUrl"/> is whitelisted on the
    /// client's <c>ChangeEmailUris</c>.
    /// </summary>
    Task<ChangeEmailRequestResponse> ChangeEmailRequestAsync(ChangeEmailRequestRequest request, CancellationToken ct = default);

    /// <summary>
    /// Completes the change-of-e-mail flow by verifying + atomically consuming the
    /// confirmation token issued earlier (via e-mail to the new address) and atomically
    /// swapping the user's e-mail to the new value while flipping
    /// <c>UserProps.EmailVerified=true</c>. The swap is only applied when the user's
    /// current address still matches the snapshot captured at issue time. All failure
    /// modes return a generic <c>invalid_token</c> response; granular reason is recorded
    /// only in audit logs. This call does NOT require any prior authentication.
    /// </summary>
    Task<ChangeEmailConfirmResponse> ChangeEmailConfirmAsync(ChangeEmailConfirmRequest request, CancellationToken ct = default);
}

public sealed partial class IdentityClient
{
    private const string MeChangeEmailBase = "/api/v1/identity/me/change-email";
    private const string AccountChangeEmailBase = "/api/v1/identity/account/change-email";

    public async Task<ChangeEmailRequestResponse> ChangeEmailRequestAsync(ChangeEmailRequestRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{MeChangeEmailBase}/request", request, _json, ct).ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();
        return await resp.ReadJsonAsync<ChangeEmailRequestResponse>(ct).ConfigureAwait(false)
               ?? new ChangeEmailRequestResponse { Success = false };
    }

    public async Task<ChangeEmailConfirmResponse> ChangeEmailConfirmAsync(ChangeEmailConfirmRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{AccountChangeEmailBase}/confirm", request, _json, ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
        {
            return new ChangeEmailConfirmResponse
            {
                Success = false,
                Error = "invalid_token",
                ErrorDescription = "The confirmation token is invalid or has expired.",
            };
        }
        return await resp.ReadJsonAsync<ChangeEmailConfirmResponse>(ct).ConfigureAwait(false)
               ?? new ChangeEmailConfirmResponse { Success = false, Error = "invalid_response" };
    }
}
