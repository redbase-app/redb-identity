using redb.Identity.Contracts.Configuration;

namespace redb.Identity.Http.Processors;

/// <summary>
/// C9 — single point that formats every <c>Set-Cookie</c> header Identity emits, so
/// security flags (<c>Secure</c> / <c>HttpOnly</c> / <c>SameSite</c> / name prefix)
/// stay consistent across session, federation-binding, and clear flows.
/// </summary>
internal static class IdentityCookieFormatter
{
    /// <summary>
    /// Builds a <c>Set-Cookie</c> header value with consistent flags.
    /// </summary>
    /// <param name="bareName">Cookie name without any prefix.</param>
    /// <param name="value">Cookie value (already URL-safe — caller's responsibility).</param>
    /// <param name="maxAgeSeconds">Cookie lifetime; pass <c>0</c> to clear.</param>
    /// <param name="secure">When <c>true</c>, the <c>Secure</c> flag is appended.</param>
    /// <param name="sameSite">SameSite mode.</param>
    /// <param name="useHostPrefix">When <c>true</c> AND <paramref name="secure"/> is true,
    /// the cookie name is prefixed with <c>__Host-</c>. The prefix is silently dropped
    /// over plain http to avoid emitting a cookie that browsers would reject.</param>
    public static string Build(
        string bareName,
        string value,
        int maxAgeSeconds,
        bool secure,
        CookieSameSiteMode sameSite,
        bool useHostPrefix = false)
    {
        if (string.IsNullOrEmpty(bareName))
            throw new ArgumentException("Cookie name is required.", nameof(bareName));

        // __Host- requires Secure + Path=/ + no Domain (RFC 6265bis §4.1.3.2).
        // Strip the prefix when not over https — otherwise the browser silently drops
        // the cookie and the user appears to be perpetually logged out.
        var canPrefix = useHostPrefix && secure;
        var name = canPrefix ? "__Host-" + bareName : bareName;

        var sb = new System.Text.StringBuilder(96);
        sb.Append(name).Append('=').Append(value);
        sb.Append("; Path=/");
        sb.Append("; Max-Age=").Append(maxAgeSeconds);
        sb.Append("; HttpOnly");
        if (secure) sb.Append("; Secure");
        sb.Append("; SameSite=").Append(SameSiteToken(sameSite));
        return sb.ToString();
    }

    /// <summary>
    /// Returns both candidate names (prefixed and bare) so cookie readers can match
    /// either while a deployment is rolling out the <c>__Host-</c> prefix.
    /// </summary>
    public static (string prefixed, string bare) Candidates(string bareName)
        => ("__Host-" + bareName, bareName);

    /// <summary>
    /// Adds a cookie to the response message, keeping any already there.
    /// <para>
    /// Two cookies must leave as two <c>Set-Cookie</c> lines. Joined into one value they are read by a
    /// browser as a single cookie — it does not split on commas (RFC 6265 §3) — with every attribute of
    /// the second appended to the first, and of several <c>Max-Age</c> attributes the last wins. The
    /// federation callback once folded a session cookie with the binding cookie's expiry that way, and
    /// the browser deleted the session as it arrived. Assigning the header instead of adding to it loses
    /// the first cookie outright. The HTTP consumer writes an array value as one line per entry, so a
    /// second cookie turns the value into an array; a single cookie stays the plain string every reader of
    /// the header already expects.
    /// </para>
    /// </summary>
    public static void AddSetCookie(IDictionary<string, object?> headers, string cookie)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentException.ThrowIfNullOrEmpty(cookie);

        if (!headers.TryGetValue("Set-Cookie", out var existing) || existing is null or string { Length: 0 })
        {
            headers["Set-Cookie"] = cookie;
            return;
        }

        headers["Set-Cookie"] = existing switch
        {
            string single => new[] { single, cookie },
            string[] several => [.. several, cookie],
            // Identity only ever writes strings built by Build; anything else is not ours to reinterpret.
            _ => throw new InvalidOperationException(
                $"Set-Cookie already holds a {existing.GetType().Name}; expected a string or string[]."),
        };
    }

    private static string SameSiteToken(CookieSameSiteMode mode) => mode switch
    {
        CookieSameSiteMode.Strict => "Strict",
        CookieSameSiteMode.Lax => "Lax",
        CookieSameSiteMode.None => "None",
        _ => "Lax"
    };
}
