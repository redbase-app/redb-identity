using redb.Route.Abstractions;
using redb.Route.Http;
using redb.Identity.Contracts.Configuration;

namespace redb.Identity.Http.Processors;

/// <summary>
/// B3 §4: HTTP-facade processors that materialize the <c>mfa_state</c> as an
/// HttpOnly <c>__Host-redb.identity.mfa</c> cookie.
/// <para>
/// Core processors (<c>redb.Identity.Core/Routes/Processors</c>) stay transport-agnostic
/// — they emit / consume <c>mfa_state</c> as a body field and these facade processors
/// bridge that field to/from the cookie. Keeps the core free of
/// <c>Request</c>/<c>Response</c>/<c>Cookie</c> types while still meeting B3 DoD
/// ("<c>mfa_state</c> в URL больше нет; cookie <c>__Host-redb.identity.mfa</c>").
/// </para>
/// </summary>
internal static class MfaCookieProcessors
{
    /// <summary>Bare cookie name (<c>__Host-</c> prefix applied automatically over https).</summary>
    internal const string BareCookieName = "redb.identity.mfa";

    /// <summary>
    /// Ingress: if the request carries the <c>__Host-redb.identity.mfa</c> (or bare)
    /// cookie, copies its value into <c>body["mfa_state"]</c> (when the body is an
    /// <see cref="IDictionary{TKey,TValue}"/> and lacks a non-empty value there) so
    /// every downstream body-reading core processor picks it up transparently. The
    /// cookie value is also stashed in <c>exchange.Properties["mfa-state-from-cookie"]</c>
    /// so GET-page renderers can fall back to it when the query string lacks <c>mfa_state</c>.
    /// </summary>
    internal static Task ReadMfaStateCookie(IExchange e, CancellationToken ct)
    {
        var cookieHeader = e.In.GetHeader<string>("Cookie");
        if (string.IsNullOrEmpty(cookieHeader))
            return Task.CompletedTask;

        var (prefixed, bare) = IdentityCookieFormatter.Candidates(BareCookieName);
        var value = ParseCookieValue(cookieHeader, prefixed)
                    ?? ParseCookieValue(cookieHeader, bare);
        if (string.IsNullOrEmpty(value))
            return Task.CompletedTask;

        e.Properties["mfa-state-from-cookie"] = value;

        if (e.In.Body is IDictionary<string, object?> body)
        {
            var existing = body.TryGetValue("mfa_state", out var cur) ? cur?.ToString() : null;
            if (string.IsNullOrEmpty(existing))
                body["mfa_state"] = value;
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Egress for login + challenge: if the core response body carries a non-empty
    /// <c>mfa_state</c>, emits <c>Set-Cookie __Host-redb.identity.mfa=...</c>. Caller
    /// wires this right after the core endpoint on POST <c>/login</c> (mfa-required case)
    /// and POST <c>/mfa/challenge</c> (OTP re-issue).
    /// </summary>
    internal static Task WriteMfaStateCookie(
        IExchange e, CancellationToken ct,
        bool secure, CookieSameSiteMode sameSite, bool useHostPrefix,
        TimeSpan maxAge)
    {
        var msg = e.HasOut ? (IMessage)e.Out! : e.In;
        var state = BodyState(msg);
        if (string.IsNullOrEmpty(state))
            return Task.CompletedTask;

        AppendSetCookie(msg, IdentityCookieFormatter.Build(
            BareCookieName, value: state, maxAgeSeconds: (int)maxAge.TotalSeconds,
            secure: secure, sameSite: sameSite, useHostPrefix: useHostPrefix));
        return Task.CompletedTask;
    }

    /// <summary>
    /// Egress for verify + recovery success: if the core response body has
    /// <c>success == true</c>, emits a Max-Age=0 deletion cookie. No-op on failure
    /// (leaves the cookie intact so the user can retry).
    /// </summary>
    internal static Task ClearMfaStateCookieOnSuccess(
        IExchange e, CancellationToken ct,
        bool secure, CookieSameSiteMode sameSite, bool useHostPrefix)
    {
        var msg = e.HasOut ? (IMessage)e.Out! : e.In;
        if (msg.Body is not IDictionary<string, object?> body) return Task.CompletedTask;
        if (!body.TryGetValue("success", out var s) || s is not true) return Task.CompletedTask;

        AppendSetCookie(msg, IdentityCookieFormatter.Build(
            BareCookieName, value: string.Empty, maxAgeSeconds: 0,
            secure: secure, sameSite: sameSite, useHostPrefix: useHostPrefix));
        return Task.CompletedTask;
    }

    // ── helpers ──

    private static string? BodyState(IMessage msg) =>
        msg.Body is IDictionary<string, object?> d && d.TryGetValue("mfa_state", out var v)
            ? v?.ToString()
            : null;

    /// <summary>
    /// Appends a Set-Cookie value to the response message, preserving any previous
    /// Set-Cookie (e.g. the session cookie written upstream). HTTP allows multiple
    /// Set-Cookie headers; transport adapters typically accept a string[] / IList.
    /// </summary>
    private static void AppendSetCookie(IMessage msg, string setCookieValue)
    {
        if (msg.Headers.TryGetValue("Set-Cookie", out var existing) && existing is not null)
        {
            if (existing is string[] arr)
                msg.Headers["Set-Cookie"] = arr.Append(setCookieValue).ToArray();
            else if (existing is System.Collections.IList list)
            {
                list.Add(setCookieValue);
                msg.Headers["Set-Cookie"] = list;
            }
            else
            {
                msg.Headers["Set-Cookie"] = new[] { existing.ToString()!, setCookieValue };
            }
        }
        else
        {
            msg.Headers["Set-Cookie"] = setCookieValue;
        }
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
