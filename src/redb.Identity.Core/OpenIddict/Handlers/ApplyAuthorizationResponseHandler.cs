using System.Net;
using System.Text;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using redb.Route.Http;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Core.OpenIddict.Handlers;

/// <summary>
/// Writes the authorization response to <see cref="IExchange.Out"/>.
/// Handles OIDC <c>response_mode</c> dispatch:
/// <list type="bullet">
/// <item><c>query</c> &#8594; 302 redirect with parameters in URL query string.</item>
/// <item><c>fragment</c> &#8594; 302 redirect with parameters in URL fragment.</item>
/// <item><c>form_post</c> &#8594; 200 HTML page with auto-submit form (OIDC FAPI form_post §1).</item>
/// </list>
/// When <c>RedirectUri</c> is absent (e.g. validation errors before redirect resolution),
/// the response is emitted as JSON for the OAuth wire profile.
/// </summary>
internal sealed class ApplyAuthorizationResponseHandler
    : IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
            .UseSingletonHandler<ApplyAuthorizationResponseHandler>()
            .SetOrder(int.MaxValue - 50_000)
            .Build();

    public ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
    {
        var exchange = context.Transaction.GetRouteExchange();
        if (exchange is null)
            return default;

        var redirectUri = context.RedirectUri;

        // OpenIddict does not auto-populate context.RedirectUri when a Reject() fires from
        // the HandleAuthorizationRequest stage (e.g. prompt=none → login_required, consent_required).
        // RFC 6749 §4.1.2.1 requires errors to be reported via the validated redirect_uri whenever
        // possible — so when we have an error AND the request carried a validated redirect_uri,
        // promote it as the response target. We only do this when the response actually carries
        // an error code, so success paths still rely on OpenIddict's canonical population.
        if (string.IsNullOrEmpty(redirectUri) && !string.IsNullOrEmpty(context.Response.Error))
        {
            redirectUri = context.Request?.RedirectUri;
        }

        if (string.IsNullOrEmpty(redirectUri))
        {
            // No redirect target — emit JSON (e.g. invalid_request before client/redirect resolution).
            RedbRouteOpenIddictServerHelpers.WriteResponseToExchange(exchange, context.Response);
            context.HandleRequest();
            return default;
        }

        // For non-HTTP callers (direct-vm, tests) there is no browser to follow a redirect.
        // Return the response parameters as a JSON dict so callers can read code/state directly.
        // Browser requests always carry redbHttp.Method (set by the HTTP consumer).
        if (!exchange.In.Headers.ContainsKey(HttpHeaders.Method))
        {
            RedbRouteOpenIddictServerHelpers.WriteResponseToExchange(exchange, context.Response);
            context.HandleRequest();
            return default;
        }

        // Default response_mode per OIDC §3.1.2.1: query for code flow, fragment for implicit/hybrid.
        var mode = context.ResponseMode;
        if (string.IsNullOrEmpty(mode))
            mode = "query";

        switch (mode)
        {
            case "form_post":
                EmitFormPost(exchange, redirectUri, context.Response);
                break;
            case "fragment":
                EmitRedirect(exchange, redirectUri, context.Response, useFragment: true);
                break;
            default: // "query"
                EmitRedirect(exchange, redirectUri, context.Response, useFragment: false);
                break;
        }

        context.HandleRequest();
        return default;
    }

    private static void EmitRedirect(
        redb.Route.Abstractions.IExchange exchange,
        string redirectUri,
        OpenIddictResponse response,
        bool useFragment)
    {
        var query = BuildQueryString(response);

        string location;
        if (useFragment)
        {
            location = redirectUri + "#" + query;
        }
        else
        {
            var sep = redirectUri.Contains('?') ? "&" : "?";
            location = redirectUri + sep + query;
        }

        EnsureOut(exchange);
        var msg = exchange.Out!;
        // Empty byte[] body so HttpConsumer copies headers (it skips header copy when Body is null).
        msg.Body = Array.Empty<byte>();
        msg.Headers[HttpHeaders.ResponseCode] = 302;
        msg.Headers["Location"] = location;
    }

    private static void EmitFormPost(
        redb.Route.Abstractions.IExchange exchange,
        string redirectUri,
        OpenIddictResponse response)
    {
        var sb = new StringBuilder(512);
        sb.Append("<!DOCTYPE html><html><head><title>Submit</title></head><body onload=\"document.forms[0].submit()\">");
        sb.Append("<form method=\"post\" action=\"");
        sb.Append(WebUtility.HtmlEncode(redirectUri));
        sb.Append("\">");

        foreach (var p in response.GetParameters())
        {
            var value = p.Value.Value?.ToString();
            if (value is null) continue;
            sb.Append("<input type=\"hidden\" name=\"");
            sb.Append(WebUtility.HtmlEncode(p.Key));
            sb.Append("\" value=\"");
            sb.Append(WebUtility.HtmlEncode(value));
            sb.Append("\"/>");
        }
        sb.Append("<noscript><button type=\"submit\">Continue</button></noscript>");
        sb.Append("</form></body></html>");

        EnsureOut(exchange);
        var msg = exchange.Out!;
        msg.Body = Encoding.UTF8.GetBytes(sb.ToString());
        msg.ContentType = "text/html; charset=utf-8";
        msg.Headers[HttpHeaders.ResponseCode] = 200;
        msg.Headers[HttpHeaders.ResponseContentType] = "text/html; charset=utf-8";
    }

    private static string BuildQueryString(OpenIddictResponse response)
    {
        var sb = new StringBuilder();
        var first = true;
        foreach (var p in response.GetParameters())
        {
            var value = p.Value.Value?.ToString();
            if (value is null) continue;
            if (!first) sb.Append('&');
            first = false;
            sb.Append(Uri.EscapeDataString(p.Key));
            sb.Append('=');
            sb.Append(Uri.EscapeDataString(value));
        }
        return sb.ToString();
    }

    private static void EnsureOut(redb.Route.Abstractions.IExchange exchange)
    {
        if (exchange.Out is not null) return;
        exchange.Pattern = redb.Route.Abstractions.ExchangePattern.InOut;
        exchange.Out = exchange.In.Clone();
        exchange.Out.Body = null;
        exchange.Out.Headers.Clear();
    }
}
