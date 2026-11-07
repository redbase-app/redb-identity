using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;

namespace redb.Identity.Web.Auth;

/// <summary>
/// N7-3 — BFF-side state for an admin impersonation overlay ("view-as" mode).
/// Persisted as a separate DataProtection-signed cookie, independent of the auth cookie,
/// so the admin's own session and tokens are never replaced. UI pages and the BFF read
/// this overlay to scope queries / forms to the target user.
/// </summary>
public sealed record ImpersonationOverlay(
    long TargetUserId,
    string TargetLogin,
    string AdminSubject,
    DateTimeOffset StartedAt);

/// <summary>
/// Reads / writes the impersonation overlay cookie. Cookie lives at most 1 hour and is
/// cleared either by the admin clicking "Stop" or implicitly when the BFF auth cookie expires.
/// </summary>
public sealed class ImpersonationStateProtector
{
    public const string CookieName = "identity.web.impersonate";
    public static readonly TimeSpan MaxLifetime = TimeSpan.FromHours(1);

    private readonly IDataProtector _protector;

    public ImpersonationStateProtector(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("redb.Identity.Web.Impersonation.v1");
    }

    public string Protect(ImpersonationOverlay overlay)
    {
        var json = JsonSerializer.Serialize(overlay);
        return _protector.Protect(json);
    }

    public ImpersonationOverlay? Unprotect(string? payload)
    {
        if (string.IsNullOrEmpty(payload)) return null;
        try
        {
            var json = _protector.Unprotect(payload);
            var overlay = JsonSerializer.Deserialize<ImpersonationOverlay>(json);
            if (overlay is null) return null;
            if (DateTimeOffset.UtcNow - overlay.StartedAt > MaxLifetime) return null;
            return overlay;
        }
        catch
        {
            return null;
        }
    }

    public void WriteCookie(HttpContext ctx, ImpersonationOverlay overlay)
    {
        ctx.Response.Cookies.Append(CookieName, Protect(overlay), new CookieOptions
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

    public ImpersonationOverlay? ReadCookie(HttpContext ctx)
    {
        if (!ctx.Request.Cookies.TryGetValue(CookieName, out var raw)) return null;
        return Unprotect(raw);
    }
}
