using System.Net;
using redb.Identity.Http.Security;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.Http;

namespace redb.Identity.Http.Processors;

/// <summary>
/// HTTP processors for rendering the consent page and handling consent submission.
/// </summary>
internal static class ConsentPageProcessors
{
    /// <summary>Consent ticket lifetime — the window a user has to act on the consent screen.</summary>
    internal static readonly TimeSpan ConsentTicketMaxAge = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Renders the consent page from a server-signed ticket (<c>?ct=…</c>) minted by
    /// <see cref="SessionCookieProcessors.RedirectToConsent"/>. The application name and the
    /// requested scopes come from the ticket, never from the query string: rendering them from
    /// the URL let a crafted <c>/consent?app_name=Your%20Bank&amp;client_id=attacker</c> link
    /// show the operator's own trusted UI for an attacker's client. A missing or invalid ticket
    /// is refused rather than rendered.
    /// </summary>
    internal static Task RenderConsentPage(
        IExchange e, CancellationToken ct,
        SessionTicketService ticketService,
        string consentPath = "/consent", IdentityTransportOptions? opts = null)
    {
        opts ??= new IdentityTransportOptions();

        var query = e.In.GetHeader<string>(HttpHeaders.Query) ?? "";
        var @params = ParseQueryParams(query);

        var ticketValue = @params.GetValueOrDefault("ct") ?? "";
        var ticket = ticketService.UnprotectConsent(ticketValue, ConsentTicketMaxAge);
        if (ticket is null)
        {
            var card = "<h1>Request expired</h1>"
                     + "<p>This authorization request is missing or has expired. Start again from the application.</p>";
            e.Out = new Message(IdentityPageTemplates.WrapPage("Request expired", card, opts));
            e.Out.Headers[HttpHeaders.ResponseContentType] = "text/html; charset=utf-8";
            e.Out.Headers[HttpHeaders.ResponseCode] = (int)HttpStatusCode.BadRequest;
            return Task.CompletedTask;
        }

        var scopeItems = string.IsNullOrEmpty(ticket.Scopes)
            ? ""
            : string.Join("\n",
                ticket.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                    .Select(s => $"<li>{WebUtility.HtmlEncode(s)}</li>"));

        var cardContent = $$"""
            <h1>Authorize Application</h1>
            <p><span class="app-name">{{WebUtility.HtmlEncode(ticket.AppName)}}</span> is requesting access to your account.</p>
            {{(string.IsNullOrEmpty(scopeItems) ? "" : $"<p>Requested permissions:</p>\n<ul>{scopeItems}</ul>")}}
            <form method="POST" action="{{WebUtility.HtmlEncode(consentPath)}}">
                <input type="hidden" name="ct" value="{{WebUtility.HtmlEncode(ticketValue)}}" />
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
    /// Maps the decision to the body the Core <c>ConsentGrantProcessor</c> expects.
    /// <para>
    /// The user is always the one the session cookie identifies (<c>session_user_id</c> header
    /// set by <c>ReadSessionCookie</c>) — never a form field. The form used to carry
    /// <c>user_id</c> and this processor preferred it over the session, while
    /// <c>ReadSessionCookie</c> lets a cookie-less request through: an anonymous cross-site POST
    /// could record any user's consent for any client. Without a session the POST is refused
    /// with 401 and nothing downstream runs.
    /// </para>
    /// <para>
    /// Two callers, one gate. Our own consent page submits a server-signed ticket (<c>ct</c>):
    /// the client id and scopes come from the ticket, and the ticket must have been minted for
    /// the session's user (a ticket cannot be replayed under someone else's session). The
    /// console's BFF (<c>RecordConsentGrantAsync</c>) has no ticket — it renders its own screen
    /// and posts <c>client_id</c>/<c>scopes</c> with the session cookie; that path stays
    /// session-bound as before.
    /// </para>
    /// </summary>
    internal static Task PrepareConsentBody(
        IExchange e, CancellationToken ct, SessionTicketService ticketService, IdentityTransportOptions opts)
    {
        // Session first, body shape second — a non-form body must not slip past the gate.
        long userId = 0;
        if (e.In.Headers.TryGetValue(SessionCookieProcessors.SessionUserIdHeader, out var hdr))
        {
            if (hdr is long hl) userId = hl;
            else if (hdr is string hs && long.TryParse(hs, out var hp)) userId = hp;
        }

        if (userId <= 0)
            return RejectConsent(e, opts, HttpStatusCode.Unauthorized, "Sign in required",
                "Your session has expired or is missing. Sign in again to review this request.",
                "Consent decision without a session.");

        if (e.In.Body is not IDictionary<string, object?> form)
            return RejectConsent(e, opts, HttpStatusCode.BadRequest, "Invalid request",
                "The consent decision must be submitted as a form.",
                "Consent decision with a non-form body.");

        var decision = form.TryGetValue("decision", out var d) ? d?.ToString() : null;
        string? clientId;
        string? scopes;
        string? returnUrl;

        var ticketValue = form.TryGetValue("ct", out var ctv) ? ctv?.ToString() : null;
        if (!string.IsNullOrEmpty(ticketValue))
        {
            // Our own consent page: parameters come from the signed ticket, not the form.
            var ticket = ticketService.UnprotectConsent(ticketValue, ConsentTicketMaxAge);
            if (ticket is null)
                return RejectConsent(e, opts, HttpStatusCode.BadRequest, "Request expired",
                    "This authorization request is missing or has expired. Start again from the application.",
                    "Consent decision with an invalid ticket.");

            if (ticket.UserId != userId)
                return RejectConsent(e, opts, HttpStatusCode.Forbidden, "Request blocked",
                    "This authorization request was issued for a different session.",
                    "Consent ticket replayed under another session.");

            clientId = ticket.ClientId;
            scopes = ticket.Scopes;
            returnUrl = ticket.ReturnUrl;
        }
        else
        {
            // BFF path (RecordConsentGrantAsync): no ticket, session-bound, form-supplied params.
            clientId = form.TryGetValue("client_id", out var cid) ? cid?.ToString() : null;
            scopes = form.TryGetValue("scopes", out var sc) ? sc?.ToString() : null;
            returnUrl = form.TryGetValue("returnUrl", out var ru) ? ru?.ToString() : null;
        }

        // Stash decision + returnUrl in Properties for HandleConsentResponse
        e.Properties["consent_decision"] = decision ?? "allow";
        if (returnUrl is not null)
            e.Properties["consent_return_url"] = returnUrl;

        e.In.Body = new Dictionary<string, object?>
        {
            ["userId"] = userId,
            ["clientId"] = clientId,
            ["scopes"] = scopes
        };

        return Task.CompletedTask;
    }

    private static Task RejectConsent(
        IExchange e, IdentityTransportOptions opts, HttpStatusCode code,
        string title, string message, string reason)
    {
        var msg = new Message(IdentityPageTemplates.WrapPage(title, $"<h1>{title}</h1><p>{message}</p>", opts));
        msg.Headers[HttpHeaders.ResponseContentType] = "text/html; charset=utf-8";
        msg.Headers[HttpHeaders.ResponseCode] = (int)code;
        HttpIdentityProcessors.AttachSecurityHeaders(msg);
        e.Out = msg;
        e.Exception = new UnauthorizedAccessException(reason);
        e.ExceptionHandled = true;
        e.Stop();
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
