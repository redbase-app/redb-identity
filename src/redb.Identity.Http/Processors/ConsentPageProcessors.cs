using System.Net;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.Http;

namespace redb.Identity.Http.Processors;

/// <summary>
/// HTTP processors for rendering the consent page and handling consent submission.
/// </summary>
internal static class ConsentPageProcessors
{
    /// <summary>
    /// Renders a consent page showing the application name and requested scopes.
    /// Query params: <c>client_id</c>, <c>app_name</c>, <c>scopes</c>, <c>user_id</c>, <c>returnUrl</c>.
    /// </summary>
    internal static Task RenderConsentPage(
        IExchange e, CancellationToken ct,
        string consentPath = "/consent", IdentityTransportOptions? opts = null)
    {
        opts ??= new IdentityTransportOptions();

        var query = e.In.GetHeader<string>(HttpHeaders.Query) ?? "";
        var @params = ParseQueryParams(query);

        var clientId = @params.GetValueOrDefault("client_id") ?? "";
        var appName = @params.GetValueOrDefault("app_name") ?? clientId;
        var scopes = @params.GetValueOrDefault("scopes") ?? "";
        var userId = @params.GetValueOrDefault("user_id") ?? "";
        var returnUrl = @params.GetValueOrDefault("returnUrl") ?? "";

        var scopeItems = string.IsNullOrEmpty(scopes)
            ? ""
            : string.Join("\n",
                scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                    .Select(s => $"<li>{WebUtility.HtmlEncode(s)}</li>"));

        var cardContent = $$"""
            <h1>Authorize Application</h1>
            <p><span class="app-name">{{WebUtility.HtmlEncode(appName)}}</span> is requesting access to your account.</p>
            {{(string.IsNullOrEmpty(scopeItems) ? "" : $"<p>Requested permissions:</p>\n<ul>{scopeItems}</ul>")}}
            <form method="POST" action="{{WebUtility.HtmlEncode(consentPath)}}">
                <input type="hidden" name="client_id" value="{{WebUtility.HtmlEncode(clientId)}}" />
                <input type="hidden" name="user_id" value="{{WebUtility.HtmlEncode(userId)}}" />
                <input type="hidden" name="scopes" value="{{WebUtility.HtmlEncode(scopes)}}" />
                <input type="hidden" name="returnUrl" value="{{WebUtility.HtmlEncode(returnUrl)}}" />
                <div class="actions">
                    <button type="submit" name="decision" value="deny" class="btn btn-secondary">Deny</button>
                    <button type="submit" name="decision" value="allow" class="btn btn-primary">Allow</button>
                </div>
            </form>
            """;

        e.Out = new Message();
        e.Out.Body = IdentityPageTemplates.WrapPage("Authorize", cardContent, opts);
        e.Out.Headers[HttpHeaders.ResponseContentType] = "text/html; charset=utf-8";
        e.Out.Headers[HttpHeaders.ResponseCode] = 200;

        return Task.CompletedTask;
    }

    /// <summary>
    /// Prepares the body for the Core <c>ConsentGrantProcessor</c> behind <c>direct-vm://identity-consent-grant</c>.
    /// Maps form fields (<c>client_id</c>, <c>user_id</c>, <c>scopes</c>) to the expected body format.
    /// Falls back to <c>session_user_id</c> header (from ReadSessionCookie) if <c>user_id</c> not in form.
    /// If user clicked "deny", stops the pipeline (body stays as form data for HandleConsentResponse).
    /// </summary>
    internal static Task PrepareConsentBody(IExchange e, CancellationToken ct)
    {
        if (e.In.Body is not IDictionary<string, object?> form)
            return Task.CompletedTask;

        var decision = form.TryGetValue("decision", out var d) ? d?.ToString() : null;
        var returnUrl = form.TryGetValue("returnUrl", out var ru) ? ru?.ToString() : null;

        // Stash decision + returnUrl in Properties for HandleConsentResponse
        e.Properties["consent_decision"] = decision ?? "allow";
        if (returnUrl is not null)
            e.Properties["consent_return_url"] = returnUrl;

        // Map form field names to ConsentGrantProcessor expected format
        var clientId = form.TryGetValue("client_id", out var cid) ? cid?.ToString() : null;
        var scopes = form.TryGetValue("scopes", out var sc) ? sc?.ToString() : null;

        // userId: prefer form, fallback to session cookie header
        long userId = 0;
        if (form.TryGetValue("user_id", out var uid))
        {
            if (uid is long l) userId = l;
            else if (uid is string s && long.TryParse(s, out var parsed)) userId = parsed;
        }

        if (userId <= 0
            && e.In.Headers.TryGetValue(SessionCookieProcessors.SessionUserIdHeader, out var hdr))
        {
            if (hdr is long hl) userId = hl;
            else if (hdr is string hs && long.TryParse(hs, out var hp)) userId = hp;
        }

        e.In.Body = new Dictionary<string, object?>
        {
            ["userId"] = userId,
            ["clientId"] = clientId,
            ["scopes"] = scopes
        };

        return Task.CompletedTask;
    }

    /// <summary>
    /// Handles consent POST response. On success, redirects back to the original authorize URL.
    /// On deny, redirects to the client with <c>error=access_denied</c>.
    /// </summary>
    internal static Task HandleConsentResponse(IExchange e, CancellationToken ct, IdentityTransportOptions opts)
    {
        var decision = e.Properties.TryGetValue("consent_decision", out var d)
            ? d?.ToString() : "allow";
        var returnUrl = e.Properties.TryGetValue("consent_return_url", out var r)
            ? r?.ToString() : null;

        if (decision == "deny")
        {
            var cardContent = "<h1>Access Denied</h1><p>You denied the application's request.</p>";
            e.Out = new Message();
            e.Out.Body = IdentityPageTemplates.WrapPage("Access Denied", cardContent, opts);
            e.Out.Headers[HttpHeaders.ResponseContentType] = "text/html; charset=utf-8";
            e.Out.Headers[HttpHeaders.ResponseCode] = 200;
            return Task.CompletedTask;
        }

        // Allow — check ConsentGrant response and redirect to original authorize URL
        var body = (e.HasOut ? e.Out!.Body : e.In.Body) as IDictionary<string, object?>;
        var success = body is not null && body.TryGetValue("success", out var s) && s is true;

        if (success && !string.IsNullOrEmpty(returnUrl) && LoginPageProcessors.IsValidReturnUrl(returnUrl))
        {
            e.Out = new Message();
            e.Out.Headers[HttpHeaders.ResponseCode] = 302;
            e.Out.Headers["Location"] = returnUrl;
            return Task.CompletedTask;
        }

        if (success)
        {
            e.Out = new Message();
            e.Out.Body = new Dictionary<string, object?> { ["message"] = "Consent granted" };
            return Task.CompletedTask;
        }

        return Task.CompletedTask;
    }

    private static Dictionary<string, string> ParseQueryParams(string query)
    {
        var dict = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eqIdx = pair.IndexOf('=');
            if (eqIdx <= 0) continue;
            var key = Uri.UnescapeDataString(pair[..eqIdx]);
            var value = Uri.UnescapeDataString(pair[(eqIdx + 1)..]);
            dict[key] = value;
        }
        return dict;
    }
}
