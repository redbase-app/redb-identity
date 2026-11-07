using System.Net;
using redb.Identity.Contracts.Users;

namespace redb.Identity.Client;

public partial interface IIdentityClient
{
    // \u2500\u2500 /account \u2014 N-3 self-service registration (anonymous) \u2500\u2500
    /// <summary>
    /// Creates a new user account through the anonymous self-service registration
    /// endpoint <c>POST /api/v1/identity/account/register</c>. Returns
    /// <c>{ success = true, userId, login }</c> on success. Distinct from the password-
    /// recovery endpoints, this surface is NOT anti-enumeration: duplicate-login /
    /// duplicate-email collisions and weak-password violations are returned as
    /// structured <c>error</c> codes so the calling UI can render an actionable message.
    /// <para>Requires NO prior authentication.</para>
    /// </summary>
    Task<RegisterAccountResponse> RegisterAccountAsync(
        RegisterAccountRequest request,
        CancellationToken ct = default);
}

public sealed partial class IdentityClient
{
    private const string AccountBase = "/api/v1/identity/account";

    public async Task<RegisterAccountResponse> RegisterAccountAsync(
        RegisterAccountRequest request,
        CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync($"{AccountBase}/register", request, _json, ct).ConfigureAwait(false);

        // Success path \u2014 the server always returns a structured RegisterAccountResponse
        // on 2xx, so deserialize directly.
        if (resp.IsSuccessStatusCode)
        {
            return await resp.ReadJsonAsync<RegisterAccountResponse>(ct).ConfigureAwait(false)
                   ?? new RegisterAccountResponse { Success = false, Error = "invalid_response" };
        }

        // Structured failure: the processor wraps every reject path in
        // RegisterAccountResponse with a stable error code, so we forward it verbatim.
        // If body deserialization fails (e.g. 404 because the route is gated off and no
        // body is returned) fall back to a canonical "registration_disabled" envelope.
        try
        {
            var body = await resp.ReadJsonAsync<RegisterAccountResponse>(ct).ConfigureAwait(false);
            if (body is not null && !string.IsNullOrEmpty(body.Error))
                return body;
        }
        catch
        {
            // Fall through to the canonical fallback below.
        }

        var fallbackError = resp.StatusCode switch
        {
            HttpStatusCode.NotFound or HttpStatusCode.Forbidden => "registration_disabled",
            HttpStatusCode.Conflict => "duplicate",
            HttpStatusCode.BadRequest => "validation_error",
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
