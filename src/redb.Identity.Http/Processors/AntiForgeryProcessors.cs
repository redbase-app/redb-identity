using System.Net;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.Http;

namespace redb.Identity.Http.Processors;

/// <summary>
/// Cross-site request forgery guard for the facade's own HTML forms (login, consent, MFA).
///
/// <para>
/// Browsers attach <c>Origin</c> to every cross-site form POST (and <c>Referer</c> to most),
/// so a form submitted from a foreign page always announces where it came from. A request
/// whose announced origin is neither the issuer nor the host it was addressed to is
/// rejected with 403 before any processor acts on the body. A request carrying neither
/// header is let through: that is the shape of the web console's BFF, the demo scripts and
/// non-browser clients, none of which a foreign page can drive.
/// </para>
///
/// <para>
/// This complements, not replaces, the other layers: the session cookie is
/// <c>SameSite=Lax</c> (a cross-site POST does not carry it), the consent form binds the
/// user to the session rather than to a form field, and every page answers with
/// <c>X-Frame-Options: DENY</c>. An opaque <c>Origin: null</c> is treated as foreign.
/// </para>
/// </summary>
internal static class AntiForgeryProcessors
{
    internal static Task RejectCrossSiteFormPost(
        IExchange e, CancellationToken ct, Uri issuer, IdentityTransportOptions opts)
    {
        var announced = e.In.GetHeader<string>("Origin");
        if (string.IsNullOrEmpty(announced))
            announced = e.In.GetHeader<string>("Referer");
        if (string.IsNullOrEmpty(announced))
            return Task.CompletedTask;

        if (IsOwnOrigin(announced, issuer, e.In.GetHeader<string>("Host")))
            return Task.CompletedTask;

        var card = "<h1>Request blocked</h1>"
                 + "<p>This form was submitted from another site and was not processed.</p>";
        var msg = new Message(IdentityPageTemplates.WrapPage("Request blocked", card, opts));
        msg.Headers[HttpHeaders.ResponseContentType] = "text/html; charset=utf-8";
        msg.Headers[HttpHeaders.ResponseCode] = (int)HttpStatusCode.Forbidden;
        HttpIdentityProcessors.AttachSecurityHeaders(msg);
        e.Out = msg;
        e.Exception = new UnauthorizedAccessException("Cross-site form submission rejected.");
        e.ExceptionHandled = true;
        e.Stop();
        return Task.CompletedTask;
    }

    /// <summary>
    /// The announced origin is ours when its authority matches the issuer's, or the
    /// <c>Host</c> the request was addressed to (reverse proxies may present the facade
    /// under a name other than the issuer). Authorities are compared with the announced
    /// scheme's default-port rules so <c>https://op</c> and <c>op:443</c> agree.
    /// </summary>
    internal static bool IsOwnOrigin(string announced, Uri issuer, string? hostHeader)
    {
        if (!Uri.TryCreate(announced, UriKind.Absolute, out var source)
            || string.IsNullOrEmpty(source.Host))
            return false;

        if (string.Equals(source.Authority, issuer.Authority, StringComparison.OrdinalIgnoreCase))
            return true;

        return !string.IsNullOrWhiteSpace(hostHeader)
            && Uri.TryCreate($"{source.Scheme}://{hostHeader.Trim()}", UriKind.Absolute, out var addressed)
            && string.Equals(source.Authority, addressed.Authority, StringComparison.OrdinalIgnoreCase);
    }
}
