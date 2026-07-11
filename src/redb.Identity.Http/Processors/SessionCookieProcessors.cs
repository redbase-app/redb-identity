using redb.Identity.Http.Security;
using redb.Route.Abstractions;
using redb.Route.Http;
using redb.Identity.Contracts.Configuration;

namespace redb.Identity.Http.Processors;

/// <summary>
/// HTTP processors for reading and writing encrypted session cookies.
/// The cookie contains an encrypted ticket with userId + username (self-contained, no DB lookup).
/// </summary>
internal static class SessionCookieProcessors
{
    internal const string DefaultCookieName = "redb.identity.session";
    internal const string SessionUserIdHeader = "session_user_id";
    internal const string SessionUsernameHeader = "session_username";
    internal const string SessionIdHeader = "session_id";

    // Re-authentication marker (prompt=login / max_age). A DataProtection-signed cookie carrying
    // the instant re-auth was forced; on the return trip the authorize handler compares it to the
    // session's auth_time to decide whether the End-User re-authenticated. See HandleReauthCookie.
    internal const string ReauthCookieName = "redb.identity.reauth";
    internal const string ReauthMarkedSidHeader = "reauth_marked_sid"; // in: session id active when re-auth was forced (0 = none)
    internal const string ReauthSetProperty = "reauth_set";           // out: exchange prop = session id to mark (long)
    internal const string ReauthClearProperty = "reauth_clear";       // out: exchange prop = true
    private static readonly TimeSpan ReauthMarkerMaxAge = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Reads the session cookie from the HTTP request, decrypts it, and sets
    /// <c>session_user_id</c> and <c>session_username</c> headers on the exchange.
    /// Must run before routing to the authorize endpoint. Tries both the bare name
    /// and the <c>__Host-</c> prefixed variant so deployments can flip
    /// <see cref="IdentityCookieOptions.UseHostPrefix"/> without a forced re-login window.
    /// </summary>
    internal static Task ReadSessionCookie(
        IExchange e, CancellationToken ct,
        SessionTicketService ticketService, TimeSpan maxAge,
        string bareCookieName)
    {
        var cookieHeader = e.In.GetHeader<string>("Cookie");
        if (string.IsNullOrEmpty(cookieHeader))
            return Task.CompletedTask;

        // Re-auth marker (prompt=login / max_age): decode it up-front so the authorize handler can
        // tell whether the End-User re-authenticated since it forced re-auth. Independent of the
        // session cookie (it must survive the new session that /login creates).
        var (reauthPrefixed, reauthBare) = IdentityCookieFormatter.Candidates(ReauthCookieName);
        var reauthValue = ParseCookieValue(cookieHeader, reauthPrefixed)
                          ?? ParseCookieValue(cookieHeader, reauthBare);
        if (reauthValue is not null)
        {
            var reauth = ticketService.UnprotectReauth(reauthValue, ReauthMarkerMaxAge);
            if (reauth.HasValue)
                e.In.Headers[ReauthMarkedSidHeader] = reauth.Value.MarkedSessionId;
        }

        var (prefixed, bare) = IdentityCookieFormatter.Candidates(bareCookieName);
        var ticketValue = ParseCookieValue(cookieHeader, prefixed)
                          ?? ParseCookieValue(cookieHeader, bare);
        if (ticketValue is null)
            return Task.CompletedTask;

        var ticket = ticketService.Unprotect(ticketValue, maxAge);
        if (ticket is null)
            return Task.CompletedTask;

        e.In.Headers[SessionUserIdHeader] = ticket.UserId;
        e.In.Headers[SessionUsernameHeader] = ticket.Username;
        if (ticket.SessionId > 0)
            e.In.Headers[SessionIdHeader] = ticket.SessionId;

        return Task.CompletedTask;
    }

    /// <summary>
    /// Writes / clears the re-authentication marker cookie on the authorize response, driven by
    /// exchange properties the OpenIddict authorize handler set:
    /// <list type="bullet">
    ///   <item><see cref="ReauthSetProperty"/> (session id, 0 = none) → the handler is forcing re-auth
    ///   (prompt=login or max_age); mint a signed <c>redb.identity.reauth</c> cookie binding the
    ///   currently-active session so the return trip can prove the End-User signed in again.</item>
    ///   <item><see cref="ReauthClearProperty"/> → re-auth was satisfied; consume the marker (expire
    ///   the cookie) so a stale marker can never satisfy a LATER prompt=login (would be a bypass).</item>
    /// </list>
    /// Runs after the redirect processors so it appends its Set-Cookie to the final response (login
    /// redirect, consent redirect, or the success code redirect).
    /// </summary>
    internal static Task HandleReauthCookie(
        IExchange e, CancellationToken ct,
        SessionTicketService ticketService,
        bool secure, CookieSameSiteMode sameSite, bool useHostPrefix)
    {
        string? setCookie = null;

        if (e.Properties.TryGetValue(ReauthSetProperty, out var rs) && rs is long markedSessionId)
        {
            var marker = ticketService.ProtectReauth(markedSessionId);
            setCookie = IdentityCookieFormatter.Build(
                ReauthCookieName, marker,
                maxAgeSeconds: (int)ReauthMarkerMaxAge.TotalSeconds,
                secure: secure, sameSite: sameSite, useHostPrefix: useHostPrefix);
        }
        else if (e.Properties.TryGetValue(ReauthClearProperty, out var rc) && rc is true)
        {
            setCookie = IdentityCookieFormatter.Build(
                ReauthCookieName, value: string.Empty,
                maxAgeSeconds: 0,
                secure: secure, sameSite: sameSite, useHostPrefix: useHostPrefix);
        }

        if (setCookie is null)
            return Task.CompletedTask;

        var msg = e.HasOut ? e.Out! : e.In;
        // A success code-redirect never carries a Set-Cookie of its own; the login/consent
        // redirects don't either, so a single Set-Cookie is safe here.
        msg.Headers["Set-Cookie"] = setCookie;
        return Task.CompletedTask;
    }

    /// <summary>
    /// Writes the session cookie to the HTTP response after successful login.
    /// Reads userId/username from the current message body (In or Out, depending on pipeline merge state).
    /// </summary>
    internal static Task WriteSessionCookie(
        IExchange e, CancellationToken ct,
        SessionTicketService ticketService, TimeSpan maxAge,
        bool secure, string bareCookieName,
        CookieSameSiteMode sameSite, bool useHostPrefix)
    {
        // After PipelineProcessor merges Out→In, the body is on In; if Out is present, use it.
        var msg = e.HasOut ? (IMessage)e.Out! : e.In;
        var body = msg.Body as IDictionary<string, object?>;
        if (body is null)
            return Task.CompletedTask;

        if (body.TryGetValue("success", out var s) && s is true &&
            body.TryGetValue("userId", out var uid) && uid is long userId &&
            body.TryGetValue("username", out var uname) && uname is string username)
        {
            var sessionId = body.TryGetValue("sessionId", out var sid) && sid is long sId ? sId : 0L;
            var ticket = ticketService.Protect(userId, sessionId, username);

            msg.Headers["Set-Cookie"] = IdentityCookieFormatter.Build(
                bareCookieName,
                ticket,
                maxAgeSeconds: (int)maxAge.TotalSeconds,
                secure: secure,
                sameSite: sameSite,
                useHostPrefix: useHostPrefix);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Clears the session cookie (for logout). Mirrors the flags used by
    /// <see cref="WriteSessionCookie"/> so the browser actually deletes the matching cookie.
    /// </summary>
    internal static Task ClearSessionCookie(IExchange e, CancellationToken ct,
        bool secure, string bareCookieName,
        CookieSameSiteMode sameSite, bool useHostPrefix)
    {
        var msg = e.Out ?? e.In;
        msg.Headers["Set-Cookie"] = IdentityCookieFormatter.Build(
            bareCookieName,
            value: string.Empty,
            maxAgeSeconds: 0,
            secure: secure,
            sameSite: sameSite,
            useHostPrefix: useHostPrefix);
        return Task.CompletedTask;
    }

    /// <summary>
    /// Redirects to the login page when the authorize endpoint returns <c>login_required</c>.
    /// Constructs <c>/login?returnUrl=&lt;original-authorize-url&gt;</c>.
    /// </summary>
    internal static Task RedirectToLogin(
        IExchange e, CancellationToken ct, string loginPath)
    {
        // OIDC §3.1.2.6: prompt=none MUST NOT trigger any interactive UI. When the
        // OpenIddict handler rejected with login_required for that reason, it sets the
        // `prompt_none` flag — let the standard redirect-to-redirect_uri error response
        // (already wired by HandleRedirectResponse) flow through unchanged.
        if (e.Properties.TryGetValue("prompt_none", out var pn) && pn is true)
            return Task.CompletedTask;

        // PipelineProcessor merges Out→In and nulls Out between steps, so the body
        // produced by the upstream OpenIddict processor lives on In by the time we run.
        var rawBody = e.HasOut ? e.Out!.Body : e.In.Body;
        if (rawBody is not IDictionary<string, object?> body)
            return Task.CompletedTask;

        if (!body.TryGetValue("error", out var err) || err?.ToString() != "login_required")
            return Task.CompletedTask;

        // Reconstruct the original authorize URL from query string or path
        var query = e.In.GetHeader<string>(HttpHeaders.Query);
        var path = e.In.GetHeader<string>(HttpHeaders.Path) ?? "/connect/authorize";
        var originalUrl = string.IsNullOrEmpty(query) ? path : $"{path}?{query}";

        var redirectUrl = $"{loginPath}?returnUrl={Uri.EscapeDataString(originalUrl)}";

        var msg = e.HasOut ? e.Out! : e.In;
        // Empty byte[] body (not null) so HttpConsumer.WriteResponse enters the
        // header-copying branch and emits the Location header for the 302.
        msg.Body = Array.Empty<byte>();
        msg.Headers[HttpHeaders.ResponseCode] = 302;
        msg.Headers["Location"] = redirectUrl;

        return Task.CompletedTask;
    }

    /// <summary>
    /// Redirects to the consent page when the authorize endpoint returns <c>consent_required</c>.
    /// Constructs <c>/consent?client_id=…&amp;app_name=…&amp;scopes=…&amp;returnUrl=…</c>.
    /// </summary>
    internal static Task RedirectToConsent(
        IExchange e, CancellationToken ct, string consentPath)
    {
        // Same merge consideration as RedirectToLogin: body may live on In after Out→In merge.
        var rawBody = e.HasOut ? e.Out!.Body : e.In.Body;
        if (rawBody is not IDictionary<string, object?> body)
            return Task.CompletedTask;

        if (!body.TryGetValue("error", out var err) || err?.ToString() != "consent_required")
            return Task.CompletedTask;

        // Read consent details from exchange properties (set by HandleAuthorizationRequestHandler)
        var clientId = e.Properties.TryGetValue("consent_client_id", out var cid) ? cid?.ToString() : null;
        var appName = e.Properties.TryGetValue("consent_app_name", out var an) ? an?.ToString() : null;
        var scopes = e.Properties.TryGetValue("consent_scopes", out var sc) ? sc?.ToString() : null;
        var userId = e.Properties.TryGetValue("consent_user_id", out var uid) ? uid?.ToString() : null;

        if (clientId is null) return Task.CompletedTask;

        // Reconstruct the original authorize URL for post-consent redirect
        var query = e.In.GetHeader<string>(HttpHeaders.Query);
        var path = e.In.GetHeader<string>(HttpHeaders.Path) ?? "/connect/authorize";
        var originalUrl = string.IsNullOrEmpty(query) ? path : $"{path}?{query}";

        var scopesArr = string.IsNullOrEmpty(scopes)
            ? Array.Empty<string>()
            : scopes!.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        var msg = e.HasOut ? e.Out! : e.In;

        // Header-driven content negotiation: a BFF that wants to render its own native
        // consent UI sends X-Identity-Delegate-Consent: 1. We answer with a machine-
        // readable 400 JSON body instead of the browser 302 to /consent — the BFF then
        // hosts its own /consent Razor page and POSTs to /me/consents to grant.
        var delegateHeader = e.In.GetHeader<string>("X-Identity-Delegate-Consent");
        if (string.Equals(delegateHeader, "1", StringComparison.Ordinal)
            || string.Equals(delegateHeader, "true", StringComparison.OrdinalIgnoreCase))
        {
            msg.Body = new Dictionary<string, object?>
            {
                ["error"] = "consent_required",
                ["clientId"] = clientId,
                ["appName"] = appName ?? clientId,
                ["scopes"] = scopesArr,
                ["userId"] = userId ?? "",
                ["returnUrl"] = originalUrl
            };
            msg.Headers[HttpHeaders.ResponseCode] = 400;
            msg.Headers["Content-Type"] = "application/json; charset=utf-8";
            return Task.CompletedTask;
        }

        var redirectUrl = $"{consentPath}?client_id={Uri.EscapeDataString(clientId)}"
                          + $"&app_name={Uri.EscapeDataString(appName ?? clientId)}"
                          + $"&scopes={Uri.EscapeDataString(scopes ?? "")}"
                          + $"&user_id={Uri.EscapeDataString(userId ?? "")}"
                          + $"&returnUrl={Uri.EscapeDataString(originalUrl)}";

        msg.Body = Array.Empty<byte>();
        msg.Headers[HttpHeaders.ResponseCode] = 302;
        msg.Headers["Location"] = redirectUrl;

        return Task.CompletedTask;
    }

    private static string? ParseCookieValue(string cookieHeader, string name)
    {
        foreach (var part in cookieHeader.Split(';', StringSplitOptions.TrimEntries))
        {
            var eqIdx = part.IndexOf('=');
            if (eqIdx <= 0) continue;
            if (part[..eqIdx].Trim().Equals(name, StringComparison.Ordinal))
                return part[(eqIdx + 1)..].Trim();
        }
        return null;
    }
}
