using System.Net;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.Http;

namespace redb.Identity.Http.Processors;

/// <summary>
/// HTTP processors for rendering the login page and handling redirect after login.
/// </summary>
internal static class LoginPageProcessors
{
    /// <summary>
    /// Renders a login HTML form using the shared page template.
    /// Preserves <c>returnUrl</c> from the query string as a hidden field.
    /// </summary>
    internal static Task RenderLoginPage(
        IExchange e, CancellationToken ct,
        string loginPath = "/login", IdentityTransportOptions? opts = null)
    {
        opts ??= new IdentityTransportOptions();

        var query = e.In.GetHeader<string>(HttpHeaders.Query) ?? "";
        var returnUrl = "";
        foreach (var part in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eqIdx = part.IndexOf('=');
            if (eqIdx > 0 && part[..eqIdx] == "returnUrl")
            {
                returnUrl = Uri.UnescapeDataString(part[(eqIdx + 1)..]);
                break;
            }
        }

        var cardContent = $$"""
            <h1>{{WebUtility.HtmlEncode(opts.Branding.LoginTitle)}}</h1>
            <form method="POST" action="{{WebUtility.HtmlEncode(loginPath)}}">
                <input type="hidden" name="returnUrl" value="{{WebUtility.HtmlEncode(returnUrl)}}" />
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autocomplete="username" autofocus />
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required autocomplete="current-password" />
                <button type="submit" class="btn btn-primary">{{WebUtility.HtmlEncode(opts.Branding.LoginTitle)}}</button>
            </form>
            {{BuildFederationButtons(opts, returnUrl)}}
            """;

        e.Out = new Message();
        e.Out.Body = IdentityPageTemplates.WrapPage(opts.Branding.LoginTitle, cardContent, opts);
        e.Out.Headers[HttpHeaders.ResponseContentType] = "text/html; charset=utf-8";
        e.Out.Headers[HttpHeaders.ResponseCode] = 200;

        return Task.CompletedTask;
    }

    /// <summary>
    /// After successful login: redirects the user to <c>returnUrl</c>.
    /// If MFA is required: redirects to the MFA page with encrypted state.
    /// If login failed: renders the login form again with an error message.
    /// </summary>
    internal static Task HandleLoginResponse(
        IExchange e, CancellationToken ct,
        string loginPath = "/login", IdentityTransportOptions? opts = null)
    {
        opts ??= new IdentityTransportOptions();

        // After PipelineProcessor merges Out→In, the body is on In; if Out is present, use it.
        var body = (e.HasOut ? e.Out!.Body : e.In.Body) as IDictionary<string, object?>;
        if (body is null)
            return Task.CompletedTask;

        var mfaRequired = body.TryGetValue("mfa_required", out var mfa) && mfa is true;
        if (mfaRequired)
        {
            // Capture upstream Set-Cookie (session + MFA-state cookies) BEFORE we replace
            // e.Out, otherwise `e.Out = new Message()` would drop them.
            var upstreamCookie = ExtractSetCookie(e);

            var mfaUrl = opts.Paths.Mfa;

            // NOTE: HTTP transport (HttpConsumer) only copies response headers when Body is non-null,
            // so an empty byte[] body is required for the Location header to reach the client.
            e.Out = new Message();
            e.Out.Body = Array.Empty<byte>();
            e.Out.Headers[HttpHeaders.ResponseCode] = 302;
            e.Out.Headers["Location"] = mfaUrl;
            if (upstreamCookie is not null)
                e.Out.Headers["Set-Cookie"] = upstreamCookie;
            return Task.CompletedTask;
        }

        var success = body.TryGetValue("success", out var s) && s is true;
        var returnUrl = body.TryGetValue("returnUrl", out var r) ? r?.ToString() : null;

        if (success && !string.IsNullOrEmpty(returnUrl))
        {
            if (IsValidReturnUrl(returnUrl))
            {
                // HttpConsumer skips header copying when Body is null; supply an empty
                // byte[] so Location/Set-Cookie reach the client.
                e.Out = new Message();
                e.Out.Body = Array.Empty<byte>();
                e.Out.Headers[HttpHeaders.ResponseCode] = 302;
                e.Out.Headers["Location"] = returnUrl;
                if (e.In.Headers.TryGetValue("Set-Cookie", out var cookie))
                    e.Out.Headers["Set-Cookie"] = cookie;
                return Task.CompletedTask;
            }
        }

        if (success)
        {
            e.Out = new Message();
            e.Out.Body = new Dictionary<string, object?> { ["message"] = "Login successful" };
            if (e.In.Headers.TryGetValue("Set-Cookie", out var cookie))
                e.Out.Headers["Set-Cookie"] = cookie;
            return Task.CompletedTask;
        }

        // Login failed — render form again with error
        var errorDesc = body.TryGetValue("error_description", out var ed)
            ? ed?.ToString() : "Invalid credentials";

        var cardContent = $$"""
            <h1>{{WebUtility.HtmlEncode(opts.Branding.LoginTitle)}}</h1>
            <p class="error">{{WebUtility.HtmlEncode(errorDesc)}}</p>
            <form method="POST" action="{{WebUtility.HtmlEncode(loginPath)}}">
                <input type="hidden" name="returnUrl" value="{{WebUtility.HtmlEncode(returnUrl ?? "")}}" />
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autocomplete="username" autofocus />
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required autocomplete="current-password" />
                <button type="submit" class="btn btn-primary">{{WebUtility.HtmlEncode(opts.Branding.LoginTitle)}}</button>
            </form>
            {{BuildFederationButtons(opts, returnUrl ?? "")}}
            """;

        e.Out = new Message();
        e.Out.Body = IdentityPageTemplates.WrapPage(opts.Branding.LoginTitle, cardContent, opts);
        e.Out.Headers[HttpHeaders.ResponseContentType] = "text/html; charset=utf-8";
        e.Out.Headers[HttpHeaders.ResponseCode] = 200;

        return Task.CompletedTask;
    }

    /// <summary>
    /// Validates returnUrl against open redirect attacks.
    /// Only allows relative URLs starting with /.
    /// </summary>
    internal static bool IsValidReturnUrl(string? url)
    {
        if (string.IsNullOrEmpty(url))
            return false;

        if (!url.StartsWith('/'))
            return false;

        if (url.Length > 1 && (url[1] == '/' || url[1] == '\\'))
            return false;

        return true;
    }

    /// <summary>
    /// Reads any <c>Set-Cookie</c> value that upstream processors (session/mfa cookie
    /// writers) may have placed on the current message. Checks <c>Out</c> first (where
    /// they typically land), then <c>In</c> (post-pipeline merge). Returns <c>null</c>
    /// when no cookie is present.
    /// </summary>
    internal static object? ExtractSetCookie(IExchange e)
    {
        if (e.HasOut && e.Out!.Headers.TryGetValue("Set-Cookie", out var o) && o is not null)
            return o;
        if (e.In.Headers.TryGetValue("Set-Cookie", out var i) && i is not null)
            return i;
        return null;
    }

    /// <summary>
    /// Builds federation provider buttons (e.g. "Login with Google") for the login page.
    /// Returns empty string if federation is disabled or no providers are configured.
    /// </summary>
    private static string BuildFederationButtons(IdentityTransportOptions opts, string returnUrl)
    {
        if (!opts.Features.EnableFederation || opts.FederationProviders.Count == 0)
            return "";

        var sb = new System.Text.StringBuilder();
        sb.AppendLine("""<div class="federation-divider" style="margin:1.5rem 0;text-align:center;color:#64748b;font-size:0.875rem;">— or —</div>""");
        sb.AppendLine("""<div class="federation-buttons" style="display:flex;flex-direction:column;gap:0.5rem;">""");

        foreach (var provider in opts.FederationProviders.OrderBy(p => p.Priority))
        {
            var href = $"/connect/external-login?provider={Uri.EscapeDataString(provider.ProviderId)}&returnUrl={Uri.EscapeDataString(returnUrl)}";
            sb.AppendLine($"""<a href="{WebUtility.HtmlEncode(href)}" class="btn btn-secondary" style="display:block;text-align:center;padding:0.75rem;border:1px solid #e2e8f0;border-radius:0.375rem;text-decoration:none;color:#1e293b;background:#f8fafc;">{WebUtility.HtmlEncode(provider.DisplayName)}</a>""");
        }

        sb.AppendLine("</div>");
        return sb.ToString();
    }
}
