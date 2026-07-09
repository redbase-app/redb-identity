using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;

namespace redb.Identity.Web.Auth;

/// <summary>
/// Encapsulates the in-flight authorization state that needs to survive across an
/// MFA challenge round-trip. The BFF stores this in a short-lived, DataProtection-signed
/// cookie keyed to a single OIDC exchange. The host-issued <c>__Host-redb.identity.mfa</c>
/// cookie value is carried as <see cref="HostMfaStateCookie"/> so the BFF can forward it
/// back when posting the verification.
/// </summary>
public sealed record MfaInFlightState(
    string HostMfaStateCookie,
    string MfaPath,
    string AuthorizeUrl,
    string Verifier,
    string State,
    string Nonce,
    string? ReturnUrl,
    DateTimeOffset IssuedAt);

/// <summary>
/// Persists <see cref="MfaInFlightState"/> in a signed cookie via DataProtection.
/// Cookie is HttpOnly, Secure, SameSite=Lax (must survive top-level navigation back to BFF),
/// and lives for at most 10 minutes — beyond that the user must restart sign-in.
/// </summary>
public sealed class MfaChallengeStateProtector
{
    public const string CookieName = "identity.web.mfa";
    public static readonly TimeSpan MaxLifetime = TimeSpan.FromMinutes(10);

    private readonly IDataProtector _protector;

    public MfaChallengeStateProtector(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("redb.Identity.Web.MfaChallenge.v1");
    }

    public string Protect(MfaInFlightState state)
    {
        var json = JsonSerializer.Serialize(state);
        return _protector.Protect(json);
    }

    public MfaInFlightState? Unprotect(string? payload)
    {
        if (string.IsNullOrEmpty(payload)) return null;
        try
        {
            var json = _protector.Unprotect(payload);
            var state = JsonSerializer.Deserialize<MfaInFlightState>(json);
            if (state is null) return null;
            if (DateTimeOffset.UtcNow - state.IssuedAt > MaxLifetime) return null;
            return state;
        }
        catch
        {
            return null;
        }
    }

    public void WriteCookie(HttpContext ctx, MfaInFlightState state)
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

    public MfaInFlightState? ReadCookie(HttpContext ctx)
    {
        if (!ctx.Request.Cookies.TryGetValue(CookieName, out var raw)) return null;
        return Unprotect(raw);
    }
}
