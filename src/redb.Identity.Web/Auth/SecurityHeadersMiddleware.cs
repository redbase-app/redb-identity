using System.Globalization;
using Microsoft.Extensions.Options;

namespace redb.Identity.Web.Auth;

/// <summary>
/// Response-side security headers configuration.
/// Bind from <c>Identity:Web:SecurityHeaders</c>. Any property left null falls
/// back to the secure-by-default value applied by <see cref="SecurityHeadersMiddleware"/>.
/// </summary>
public sealed class SecurityHeadersOptions
{
    /// <summary>If false, the middleware is skipped entirely (useful only for local debugging).</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Custom Content-Security-Policy. When null, the default policy (see middleware) is used.</summary>
    public string? ContentSecurityPolicy { get; set; }

    /// <summary>Custom Strict-Transport-Security. Default: <c>max-age=31536000; includeSubDomains</c>.</summary>
    public string? StrictTransportSecurity { get; set; }

    /// <summary>X-Frame-Options. Default: <c>DENY</c>.</summary>
    public string? FrameOptions { get; set; }

    /// <summary>Referrer-Policy. Default: <c>strict-origin-when-cross-origin</c>.</summary>
    public string? ReferrerPolicy { get; set; }

    /// <summary>Permissions-Policy. Default: locks geolocation/camera/microphone/payment.</summary>
    public string? PermissionsPolicy { get; set; }

    /// <summary>Cross-Origin-Opener-Policy. Default: <c>same-origin</c>.</summary>
    public string? CrossOriginOpenerPolicy { get; set; }
}

/// <summary>
/// Adds production-grade security response headers to every response served by the BFF.
/// Defaults are tuned for Blazor Server (allows wss for SignalR, inline styles for
/// scoped CSS, blocks framing entirely). Override via <see cref="SecurityHeadersOptions"/>.
/// Closes F-2.5 from Phase-2 critical review.
/// </summary>
public sealed class SecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;
    private readonly SecurityHeadersOptions _opts;

    public SecurityHeadersMiddleware(RequestDelegate next, IOptions<SecurityHeadersOptions> opts)
    {
        _next = next;
        _opts = opts.Value;
    }

    public Task InvokeAsync(HttpContext context)
    {
        if (!_opts.Enabled)
            return _next(context);

        context.Response.OnStarting(static state =>
        {
            var (ctx, opts) = ((HttpContext, SecurityHeadersOptions))state;
            ApplyHeaders(ctx, opts);
            return Task.CompletedTask;
        }, (context, _opts));

        return _next(context);
    }

    private static void ApplyHeaders(HttpContext ctx, SecurityHeadersOptions opts)
    {
        var headers = ctx.Response.Headers;

        if (!headers.ContainsKey("Content-Security-Policy"))
        {
            headers["Content-Security-Policy"] = opts.ContentSecurityPolicy ?? DefaultCsp;
        }

        // HSTS only on HTTPS responses; HTTP responses must not advertise it.
        if (ctx.Request.IsHttps && !headers.ContainsKey("Strict-Transport-Security"))
        {
            headers["Strict-Transport-Security"] = opts.StrictTransportSecurity ?? DefaultHsts;
        }

        if (!headers.ContainsKey("X-Frame-Options"))
            headers["X-Frame-Options"] = opts.FrameOptions ?? "DENY";

        if (!headers.ContainsKey("X-Content-Type-Options"))
            headers["X-Content-Type-Options"] = "nosniff";

        if (!headers.ContainsKey("Referrer-Policy"))
            headers["Referrer-Policy"] = opts.ReferrerPolicy ?? "strict-origin-when-cross-origin";

        if (!headers.ContainsKey("Permissions-Policy"))
            headers["Permissions-Policy"] = opts.PermissionsPolicy ?? DefaultPermissionsPolicy;

        if (!headers.ContainsKey("Cross-Origin-Opener-Policy"))
            headers["Cross-Origin-Opener-Policy"] = opts.CrossOriginOpenerPolicy ?? "same-origin";

        // Remove the legacy Server banner that ASP.NET / Kestrel emit.
        headers.Remove("Server");
    }

    // Blazor Server-friendly CSP:
    //  - script-src 'self' (no inline scripts; QR codes use SVG, charts.js is bundled).
    //  - style-src 'self' 'unsafe-inline' — Blazor scoped CSS injects <style> blobs.
    //  - connect-src 'self' wss:/ws: — SignalR uses wss when over HTTPS, ws when HTTP (dev).
    //  - img-src 'self' data: https: — allows inline data URIs (QR codes) and provider logos.
    //  - frame-ancestors 'none' — defense-in-depth alongside X-Frame-Options.
    //  - form-action 'self' — restricts POST targets to the BFF itself.
    private const string DefaultCsp =
        "default-src 'self'; " +
        "script-src 'self' 'wasm-unsafe-eval'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data: https:; " +
        "font-src 'self' data:; " +
        "connect-src 'self' wss: ws:; " +
        "frame-ancestors 'none'; " +
        "form-action 'self'; " +
        "base-uri 'self'; " +
        "object-src 'none'";

    private static readonly string DefaultHsts = "max-age=" +
        TimeSpan.FromDays(365).TotalSeconds.ToString("F0", CultureInfo.InvariantCulture) +
        "; includeSubDomains";

    private const string DefaultPermissionsPolicy =
        "geolocation=(), camera=(), microphone=(), payment=(), usb=(), " +
        "magnetometer=(), accelerometer=(), gyroscope=(), interest-cohort=()";
}
