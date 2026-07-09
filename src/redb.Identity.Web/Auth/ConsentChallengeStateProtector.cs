using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;

namespace redb.Identity.Web.Auth;

/// <summary>
/// In-flight state carried across the BFF-native consent round-trip.
///
/// The host emits <c>consent_required</c> as a JSON 400 (instead of the legacy 302 to
/// its own HTML page) when the BFF sets <c>X-Identity-Delegate-Consent: 1</c> on
/// <c>/connect/authorize</c>. At that point the BFF still owns the original OIDC
/// authorize parameters (verifier/state/nonce) and the host session cookie jar that
/// authenticated the user a moment earlier. We need all of that to:
///   1) render a BFF-native /consent page asking the end-user to allow/deny,
///   2) POST the grant decision to the host's existing form-based
///      <c>/consent</c> endpoint with that same session cookie attached,
///   3) replay <c>/connect/authorize</c> once consent has been recorded so the
///      OIDC code is finally issued and the rest of the token exchange can complete.
///
/// Everything lives in a short-lived, DataProtection-signed cookie keyed to a single
/// OIDC exchange, exactly mirroring <see cref="MfaInFlightState"/>.
/// </summary>
public sealed record ConsentInFlightState(
    string HostSessionCookieHeader,
    string AuthorizeUrl,
    string Verifier,
    string State,
    string Nonce,
    string ClientId,
    string AppName,
    string[] Scopes,
    long UserId,
    string? ReturnUrl,
    DateTimeOffset IssuedAt);

/// <summary>
/// Persists <see cref="ConsentInFlightState"/> in a signed cookie via DataProtection.
/// Cookie is HttpOnly, Secure (when over https), SameSite=Lax so it survives the
/// top-level navigation to the BFF /consent page, and lives for at most 10 minutes —
/// past that the user must restart sign-in.
/// </summary>
public sealed class ConsentChallengeStateProtector
{
    public const string CookieName = "identity.web.consent";
    public static readonly TimeSpan MaxLifetime = TimeSpan.FromMinutes(10);

    private readonly IDataProtector _protector;

    public ConsentChallengeStateProtector(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("redb.Identity.Web.ConsentChallenge.v1");
    }

    public string Protect(ConsentInFlightState state)
    {
        var json = JsonSerializer.Serialize(state);
        return _protector.Protect(json);
    }

    public ConsentInFlightState? Unprotect(string? payload)
    {
        if (string.IsNullOrEmpty(payload)) return null;
        try
        {
            var json = _protector.Unprotect(payload);
            var state = JsonSerializer.Deserialize<ConsentInFlightState>(json);
            if (state is null) return null;
            if (DateTimeOffset.UtcNow - state.IssuedAt > MaxLifetime) return null;
            return state;
        }
        catch
        {
            return null;
        }
    }

    public void WriteCookie(HttpContext ctx, ConsentInFlightState state)
    {
        ctx.Response.Cookies.Append(CookieName, Protect(state), new CookieOptions
        {
            HttpOnly = true,
            Secure = ctx.Request.IsHttps,
            SameSite = SameSiteMode.Lax,
            Path = "/",
            MaxAge = MaxLifetime,
            IsEssential = true,
        });
    }

    public void ClearCookie(HttpContext ctx)
    {
        ctx.Response.Cookies.Delete(CookieName, new CookieOptions
        {
            HttpOnly = true,
            Secure = ctx.Request.IsHttps,
            SameSite = SameSiteMode.Lax,
            Path = "/",
        });
    }

    public ConsentInFlightState? ReadCookie(HttpContext ctx)
    {
        if (!ctx.Request.Cookies.TryGetValue(CookieName, out var raw)) return null;
        return Unprotect(raw);
    }
}
