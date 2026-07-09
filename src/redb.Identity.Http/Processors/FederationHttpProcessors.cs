using System.Net;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.Http;
using redb.Identity.Contracts.Configuration;

namespace redb.Identity.Http.Processors;

/// <summary>
/// HTTP processors for federation challenge (redirect to IdP) and callback (redirect after token exchange).
/// </summary>
internal static class FederationHttpProcessors
{
    /// <summary>
    /// Reads the per-flow browser-binding secret from the inbound <c>Cookie</c> header
    /// (if any) and stashes it on <see cref="IExchange.Properties"/> so the core
    /// callback processor can hand it to <c>FederationStateProtector.UnprotectAsync</c>.
    /// </summary>
    internal static Task ExtractBindingCookie(IExchange e, CancellationToken ct, string cookieName)
    {
        if (string.IsNullOrEmpty(cookieName))
            return Task.CompletedTask;

        if (!e.In.Headers.TryGetValue("Cookie", out var raw) || raw is not string cookieHeader)
            return Task.CompletedTask;

        // Parse RFC 6265: name=value; name2=value2 ...
        foreach (var part in cookieHeader.Split(';'))
        {
            var span = part.AsSpan().Trim();
            var eq = span.IndexOf('=');
            if (eq <= 0) continue;
            var name = span[..eq].ToString();
            if (string.Equals(name, cookieName, StringComparison.Ordinal))
            {
                e.Properties["federation-binding-secret"] = span[(eq + 1)..].ToString();
                break;
            }
        }
        return Task.CompletedTask;
    }

    /// <summary>
    /// Converts a successful challenge response (with <c>redirect_uri</c>) into an HTTP 302 redirect.
    /// On error, renders JSON error response. When the core processor minted a per-flow
    /// browser-binding secret, attaches it as a <c>Secure HttpOnly SameSite=Lax</c> cookie.
    /// </summary>
    internal static Task HandleChallengeRedirect(IExchange e, CancellationToken ct)
    {
        var body = (e.HasOut ? e.Out!.Body : e.In.Body) as IDictionary<string, object?>;
        if (body is null)
            return Task.CompletedTask;

        if (body.TryGetValue("redirect_uri", out var uri) && uri is string redirectUri
            && !string.IsNullOrEmpty(redirectUri))
        {
            e.Out = new Message();
            e.Out.Headers[HttpHeaders.ResponseCode] = 302;
            e.Out.Headers["Location"] = redirectUri;
            AttachBindingCookieIfNeeded(e, redirectUri);
            return Task.CompletedTask;
        }

        // Error — pass through for JSON serialization
        if (body.TryGetValue("error", out _))
        {
            e.Out ??= new Message();
            e.Out.Body = body;
            e.Out.Headers[HttpHeaders.ResponseCode] = 400;
        }

        return Task.CompletedTask;
    }

    private static void AttachBindingCookieIfNeeded(IExchange e, string redirectUri)
    {
        if (!e.Properties.TryGetValue("federation-binding-secret", out var sObj) || sObj is not string secret)
            return;
        if (!e.Properties.TryGetValue("federation-binding-cookie-name", out var nObj) || nObj is not string name)
            return;

        // Cookie comes back to us on the callback, so use the configured issuer-scheme flag
        // (stashed on the exchange by HttpFacadeRouteBuilder), falling back to the IdP
        // redirect scheme if the property isn't set (older callers).
        var secure = e.Properties.TryGetValue("federation-binding-secure", out var scObj) && scObj is bool sc
            ? sc
            : redirectUri.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
        var sameSite = e.Properties.TryGetValue("federation-binding-samesite", out var ssObj)
            && ssObj is CookieSameSiteMode ss ? ss : CookieSameSiteMode.Lax;
        var useHostPrefix = e.Properties.TryGetValue("federation-binding-host-prefix", out var hpObj)
            && hpObj is bool hp && hp;
        e.Out!.Headers["Set-Cookie"] = IdentityCookieFormatter.Build(
            name, secret, maxAgeSeconds: 600, secure: secure,
            sameSite: sameSite, useHostPrefix: useHostPrefix);
    }

    /// <summary>
    /// After callback processing: redirects to <c>returnUrl</c> on success,
    /// or renders an error page on failure. Always clears the per-flow binding cookie.
    /// </summary>
    internal static Task HandleCallbackResponse(
        IExchange e, CancellationToken ct, string bindingCookieName)
    {
        var body = (e.HasOut ? e.Out!.Body : e.In.Body) as IDictionary<string, object?>;
        if (body is null)
            return Task.CompletedTask;

        var success = body.TryGetValue("success", out var s) && s is true;
        var returnUrl = body.TryGetValue("returnUrl", out var r) ? r?.ToString() : null;

        if (success && !string.IsNullOrEmpty(returnUrl) && LoginPageProcessors.IsValidReturnUrl(returnUrl))
        {
            e.Out = new Message();
            e.Out.Headers[HttpHeaders.ResponseCode] = 302;
            e.Out.Headers["Location"] = returnUrl;
            CarrySessionAndClearBinding(e, bindingCookieName);
            return Task.CompletedTask;
        }

        if (success)
        {
            // No valid returnUrl — show success message
            e.Out = new Message();
            e.Out.Body = new Dictionary<string, object?> { ["message"] = "Login successful" };
            CarrySessionAndClearBinding(e, bindingCookieName);
            return Task.CompletedTask;
        }

        // Error — render error page
        var errorDesc = body.TryGetValue("error_description", out var ed) ? ed?.ToString() : "Authentication failed";

        e.Out = new Message();
        e.Out.Body = IdentityPageTemplates.WrapPage("Authentication Error",
            $"""
            <h1>Authentication Error</h1>
            <p class="error">{WebUtility.HtmlEncode(errorDesc)}</p>
            <a href="/" class="btn btn-primary">Back to Home</a>
            """,
            new IdentityTransportOptions());
        e.Out.Headers[HttpHeaders.ResponseContentType] = "text/html; charset=utf-8";
        e.Out.Headers[HttpHeaders.ResponseCode] = 200;
        AppendClearBindingCookie(e, bindingCookieName);
        return Task.CompletedTask;
    }

    private static void CarrySessionAndClearBinding(IExchange e, string bindingCookieName)
    {
        // Carry session cookie set by SessionCookieProcessors earlier in the pipeline.
        if (e.In.Headers.TryGetValue("Set-Cookie", out var session))
            e.Out!.Headers["Set-Cookie"] = session;
        AppendClearBindingCookie(e, bindingCookieName);
    }

    private static void AppendClearBindingCookie(IExchange e, string bindingCookieName)
    {
        if (string.IsNullOrEmpty(bindingCookieName)) return;
        // Mirror the Set flags so the browser actually deletes the matching cookie.
        var sameSite = e.Properties.TryGetValue("federation-binding-samesite", out var ssObj)
            && ssObj is CookieSameSiteMode ss ? ss : CookieSameSiteMode.Lax;
        var useHostPrefix = e.Properties.TryGetValue("federation-binding-host-prefix", out var hpObj)
            && hpObj is bool hp && hp;
        // Issuer-scheme drives Secure for the clear; if we set it Secure we must clear it Secure.
        var secure = e.Properties.TryGetValue("federation-binding-secure", out var scObj)
            && scObj is bool sc && sc;
        var clear = IdentityCookieFormatter.Build(
            bindingCookieName, value: string.Empty, maxAgeSeconds: 0,
            secure: secure, sameSite: sameSite, useHostPrefix: useHostPrefix);
        if (e.Out!.Headers.TryGetValue("Set-Cookie", out var existing) && existing is string es && es.Length > 0)
            e.Out!.Headers["Set-Cookie"] = es + ", " + clear;
        else
            e.Out!.Headers["Set-Cookie"] = clear;
    }
}
