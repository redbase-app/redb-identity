using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using redb.Identity.Contracts.Serialization;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.Http;

namespace redb.Identity.Http.Processors;

/// <summary>
/// HTTP-specific processors that translate between HTTP semantics and
/// the transport-agnostic <c>direct-vm://identity-*</c> exchange format.
/// All methods are stateless and suitable for use as inline route processors.
/// </summary>
internal static class HttpIdentityProcessors
{
    /// <summary>
    /// E5 — propagates a correlation id across the HTTP ↔ direct-vm boundary.
    /// <list type="bullet">
    ///   <item><description>Reads <c>X-Correlation-Id</c> from the request; if absent,
    ///   derives it from <see cref="Activity.Current"/> (W3C trace-id, which redb.Route
    ///   already attaches via <c>RouteActivitySource</c>), falling back to a new GUID.</description></item>
    ///   <item><description>Stores the value under <c>"identity:correlation-id"</c> so
    ///   downstream processors (and logger <see cref="ILogger.BeginScope"/> wrappers)
    ///   can enrich their output uniformly.</description></item>
    ///   <item><description>Sets <c>X-Correlation-Id</c> as an output header so the
    ///   response echoes the same value to the caller (RFC-style trace handoff).</description></item>
    /// </list>
    /// Safe to run first on every HTTP route — does not consume or mutate body/headers
    /// beyond the single correlation header.
    /// </summary>
    internal static Task PropagateCorrelationId(IExchange e, CancellationToken ct)
    {
        var requestId = e.In.GetHeader<string>("X-Correlation-Id");
        if (string.IsNullOrWhiteSpace(requestId))
        {
            requestId = Activity.Current?.TraceId.ToString()
                ?? Guid.NewGuid().ToString("N");
        }

        e.Properties["identity:correlation-id"] = requestId;

        return Task.CompletedTask;
    }

    /// <summary>
    /// Extracts client authentication from HTTP request:
    /// 1. Basic auth header → client_id + client_secret headers
    /// 2. Form-encoded body → client_id + client_secret headers (if not already set)
    /// Also propagates Content-Type for downstream processors.
    /// </summary>
    internal static Task MapHttpToIdentityHeaders(IExchange e, CancellationToken ct)
    {
        var authHeader = e.In.GetHeader<string>(HttpHeaders.Authorization);
        if (authHeader?.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase) == true)
        {
            var decoded = Encoding.UTF8.GetString(
                Convert.FromBase64String(authHeader[6..]));
            var parts = decoded.Split(':', 2);
            e.In.Headers["client_id"] = Uri.UnescapeDataString(parts[0]);
            if (parts.Length > 1)
                e.In.Headers["client_secret"] = Uri.UnescapeDataString(parts[1]);
        }

        // Propagate Content-Type so OpenIddict handlers can detect form vs JSON
        var contentType = e.In.GetHeader<string>(HttpHeaders.ContentType);
        if (contentType is not null)
            e.In.Headers["Content-Type"] = contentType;

        return Task.CompletedTask;
    }

    /// <summary>
    /// Extracts Bearer token from Authorization header and sets it as a header
    /// for downstream userinfo/introspect processing.
    /// </summary>
    internal static Task ExtractBearerToken(IExchange e, CancellationToken ct)
    {
        var authHeader = e.In.GetHeader<string>(HttpHeaders.Authorization);
        if (authHeader?.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) == true)
        {
            e.In.Headers["access_token"] = authHeader[7..];
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Maps HTTP query parameters to the exchange body as a dictionary.
    /// Used for GET /connect/authorize where params arrive as query string.
    /// </summary>
    internal static Task MapQueryToBody(IExchange e, CancellationToken ct)
    {
        var query = e.In.GetHeader<string>(HttpHeaders.Query);
        if (string.IsNullOrEmpty(query))
            return Task.CompletedTask;

        var dict = ParseFormUrlEncoded(query);
        e.In.Body = dict;

        return Task.CompletedTask;
    }

    /// <summary>
    /// Maps form-encoded POST body to exchange body as a dictionary.
    /// Used for POST /connect/authorize with form submission.
    /// </summary>
    internal static Task MapFormToBody(IExchange e, CancellationToken ct)
    {
        if (e.In.Body is byte[] bytes)
        {
            var text = Encoding.UTF8.GetString(bytes);
            e.In.Body = ParseFormUrlEncoded(text);
        }
        else if (e.In.Body is string formBody && !string.IsNullOrEmpty(formBody))
        {
            e.In.Body = ParseFormUrlEncoded(formBody);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Handles redirect responses from the authorize endpoint.
    /// Converts <c>redirect_uri</c> output header into HTTP 302 + Location header.
    /// </summary>
    internal static Task HandleRedirectResponse(IExchange e, CancellationToken ct)
    {
        var msg = EnsureOut(e);
        var redirectUri = msg.GetHeader<string>("redirect_uri");
        if (redirectUri is not null)
        {
            msg.Headers[HttpHeaders.ResponseCode] = 302;
            msg.Headers["Location"] = redirectUri;
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Strips the <c>/api/v1/identity/</c> prefix from <c>redbHttp.Path</c>
    /// so the controller registry can match paths like <c>applications/{id}</c>.
    /// </summary>
    internal static Task StripManagementPrefix(IExchange e, CancellationToken ct)
    {
        const string prefix = "/api/v1/identity/";
        var path = e.In.GetHeader<string>(HttpHeaders.Path);
        if (path?.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) == true)
        {
            e.In.Headers[HttpHeaders.Path] = "/" + path[prefix.Length..];
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Z2 (RFC 7592): extracts <c>client_id</c> from the <c>/connect/register/{client_id}</c>
    /// path segment and derives the <c>operation</c> header from the HTTP method
    /// (<c>GET→read</c>, <c>PUT→update</c>, <c>DELETE→delete</c>). Unsupported methods get no
    /// <c>operation</c> header; the core processor returns <c>invalid_request</c>.
    /// </summary>
    internal static Task ExtractDynamicRegistrationManagement(IExchange e, CancellationToken ct)
    {
        const string prefix = "/connect/register/";
        var path = e.In.GetHeader<string>(HttpHeaders.Path);
        if (path is not null && path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            var segment = path[prefix.Length..].TrimEnd('/');
            // Strip any query string just in case.
            var q = segment.IndexOf('?');
            if (q >= 0) segment = segment[..q];
            if (segment.Length > 0)
                e.In.Headers["client_id"] = Uri.UnescapeDataString(segment);
        }

        var method = e.In.GetHeader<string>(HttpHeaders.Method);
        var op = method?.ToUpperInvariant() switch
        {
            "GET" => "read",
            "PUT" => "update",
            "DELETE" => "delete",
            _ => null
        };
        if (op is not null)
            e.In.Headers["operation"] = op;

        return Task.CompletedTask;
    }

    // ── Private helpers ──

    private static Dictionary<string, object?> ParseFormUrlEncoded(string encoded)
    {
        var dict = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var pair in encoded.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eqIdx = pair.IndexOf('=');
            if (eqIdx < 0)
            {
                dict[Decode(pair)] = null;
                continue;
            }

            var key = Decode(pair[..eqIdx]);
            var value = Decode(pair[(eqIdx + 1)..]);
            dict[key] = value;
        }

        return dict;

        // In application/x-www-form-urlencoded, '+' encodes space
        static string Decode(string s) => Uri.UnescapeDataString(s.Replace('+', ' '));
    }

    private static string Encode(string value) =>
        System.Net.WebUtility.HtmlEncode(value);

    /// <summary>
    /// Maps OAuth2 error codes in the response body to proper HTTP status codes (RFC 6749 §5.2).
    /// Must be called BEFORE <see cref="SerializeJsonResponse"/> which converts to byte[].
    /// </summary>
    internal static Task MapOAuthErrorToHttpStatus(IExchange e, CancellationToken ct)
    {
        // Check In.Body (after PipelineProcessor merge, Out→In happens before this step)
        var body = e.HasOut ? e.Out!.Body : e.In.Body;

        string? error = null;
        if (body is IDictionary<string, object?> dictN && dictN.TryGetValue("error", out var errN))
            error = errN as string;
        else if (body is IDictionary<string, object> dictV && dictV.TryGetValue("error", out var errV))
            error = errV as string;

        if (error is null) return Task.CompletedTask;

        var statusCode = error switch
        {
            "invalid_client" => 401,
            "invalid_token" => 401,
            "invalid_request" => 400,
            "invalid_grant" => 400,
            "invalid_scope" => 400,
            "unsupported_grant_type" => 400,
            "unsupported_response_type" => 400,
            "unauthorized_client" => 400,
            "access_denied" => 400,
            "server_error" => 500,
            "temporarily_unavailable" => 503,
            _ => 400
        };

        // Set on In — survives PipelineProcessor merge and EnsureOut (which creates new Out
        // from In.Body but does not copy headers). We must set it on In so downstream
        // processors inherit it. SerializeJsonResponse will propagate it to Out.
        e.In.Headers[HttpHeaders.ResponseCode] = statusCode;
        return Task.CompletedTask;
    }

    /// <summary>
    /// Renders an authorization error as an HTML page for browsers, leaving the JSON body
    /// untouched for API clients.
    /// <para>
    /// RFC 6749 §4.1.2.1: when <c>redirect_uri</c> is missing, unregistered or malformed, the
    /// authorization server MUST NOT redirect — it has no trustworthy place to send the user, so
    /// it must inform the resource owner itself. The end user is sitting in a browser at that
    /// moment, and a raw JSON error object is not "informing the resource owner". Same for a bad
    /// <c>client_id</c>, an unsupported <c>response_type</c>, and every other authorize-time
    /// failure that cannot be bounced back to the client.
    /// </para>
    /// <para>
    /// Content negotiation, not a blanket switch: we only render HTML when the request actually
    /// prefers it (<c>Accept: text/html</c>). Machine callers that ask for JSON — or send no
    /// Accept at all — keep the exact OAuth error object they had before, so nothing on the API
    /// side changes shape. Wire AFTER <see cref="MapOAuthErrorToHttpStatus"/> (so the status code
    /// is already decided) and BEFORE <see cref="SerializeJsonResponse"/> (which would otherwise
    /// turn the dictionary into JSON bytes).
    /// </para>
    /// </summary>
    internal static Task RenderAuthorizeErrorPage(
        IExchange e, CancellationToken ct, IdentityTransportOptions opts)
    {
        var body = e.HasOut ? e.Out!.Body : e.In.Body;

        string? error = null, description = null, uri = null;
        if (body is IDictionary<string, object?> dictN)
        {
            if (dictN.TryGetValue("error", out var v)) error = v as string;
            if (dictN.TryGetValue("error_description", out var d)) description = d as string;
            if (dictN.TryGetValue("error_uri", out var u)) uri = u as string;
        }
        else if (body is IDictionary<string, object> dictV)
        {
            if (dictV.TryGetValue("error", out var v)) error = v as string;
            if (dictV.TryGetValue("error_description", out var d)) description = d as string;
            if (dictV.TryGetValue("error_uri", out var u)) uri = u as string;
        }

        if (string.IsNullOrEmpty(error)) return Task.CompletedTask;
        if (!PrefersHtml(e)) return Task.CompletedTask;

        var status = e.In.Headers.TryGetValue(HttpHeaders.ResponseCode, out var rc) ? rc : 400;

        var details = new StringBuilder();
        details.Append("<p class=\"error\">")
               .Append(WebUtility.HtmlEncode(
                   string.IsNullOrEmpty(description)
                       ? "The authorization request could not be completed."
                       : description))
               .Append("</p>");

        // The error code is what an operator greps their logs for, and what the client developer
        // has to look up in the spec — surface it verbatim rather than burying it.
        details.Append("<p><code>").Append(WebUtility.HtmlEncode(error)).Append("</code></p>");

        if (!string.IsNullOrEmpty(uri))
        {
            var safe = WebUtility.HtmlEncode(uri);
            details.Append("<p><a href=\"").Append(safe).Append("\" rel=\"noopener noreferrer\">")
                   .Append("More about this error</a></p>");
        }

        // Deliberately no "go back" / "retry" link: the whole point of §4.1.2.1 is that we do not
        // trust the URI we were handed, so we must not offer to navigate to it.
        var card = $"<h1>Authorization Error</h1>{details}";

        var msg = EnsureOut(e);
        msg.Body = IdentityPageTemplates.WrapPage("Authorization Error", card, opts);
        msg.ContentType = "text/html; charset=utf-8";
        msg.Headers[HttpHeaders.ResponseContentType] = "text/html; charset=utf-8";
        msg.Headers[HttpHeaders.ResponseCode] = status;
        e.In.Headers[HttpHeaders.ResponseContentType] = "text/html; charset=utf-8";

        return Task.CompletedTask;
    }

    /// <summary>
    /// True when the caller is a browser rendering a page rather than a client consuming an API:
    /// <c>Accept</c> lists <c>text/html</c> and does not rank an explicit <c>application/json</c>
    /// above it. A missing or wildcard-only Accept counts as "not a browser" so that curl, SDKs
    /// and the conformance suite's HTTP client keep receiving JSON.
    /// </summary>
    private static bool PrefersHtml(IExchange e)
    {
        var accept = e.In.GetHeader<string>(HttpHeaders.Accept);
        if (string.IsNullOrEmpty(accept)) return false;

        var html = accept.IndexOf("text/html", StringComparison.OrdinalIgnoreCase);
        if (html < 0) return false;

        var json = accept.IndexOf("application/json", StringComparison.OrdinalIgnoreCase);
        return json < 0 || html < json;
    }

    /// <summary>
    /// RFC 6750 §3 — userinfo (and other protected-resource) error responses MUST include
    /// the <c>WWW-Authenticate</c> header with a <c>Bearer</c> challenge. OpenIddict's
    /// default userinfo error response omits it (it's an authorization-server response
    /// shape, not a protected-resource one). Wire this processor AFTER
    /// <see cref="MapOAuthErrorToHttpStatus"/> on userinfo routes to attach the spec-mandated
    /// challenge whenever the body carries an <c>error</c> field.
    /// </summary>
    internal static Task AttachBearerChallengeOnError(IExchange e, CancellationToken ct)
    {
        var body = e.HasOut ? e.Out!.Body : e.In.Body;
        string? error = null;
        string? errorDescription = null;
        if (body is IDictionary<string, object?> dictN)
        {
            if (dictN.TryGetValue("error", out var errN)) error = errN as string;
            if (dictN.TryGetValue("error_description", out var dN)) errorDescription = dN as string;
        }
        else if (body is IDictionary<string, object> dictV)
        {
            if (dictV.TryGetValue("error", out var errV)) error = errV as string;
            if (dictV.TryGetValue("error_description", out var dV)) errorDescription = dV as string;
        }

        if (string.IsNullOrEmpty(error)) return Task.CompletedTask;

        // RFC 7235 §2.1 quoted-string rules: backslash → \\, quote → \"
        var safeError = error.Replace("\\", "\\\\").Replace("\"", "\\\"");
        var challenge = $"Bearer realm=\"identity\", error=\"{safeError}\"";
        if (!string.IsNullOrEmpty(errorDescription))
        {
            var safeDesc = errorDescription.Replace("\\", "\\\\").Replace("\"", "\\\"");
            challenge += $", error_description=\"{safeDesc}\"";
        }
        // Place on In so it survives the EnsureOut step in SerializeJsonResponse.
        e.In.Headers["WWW-Authenticate"] = challenge;
        return Task.CompletedTask;
    }

    /// <summary>
    /// Serializes the response body to JSON bytes when it is a dictionary.
    /// Required because <c>HttpConsumer.WriteResponse</c> calls <c>ToString()</c>
    /// on non-byte/stream bodies, which would produce a type name for dictionaries.
    /// </summary>
    internal static Task SerializeJsonResponse(IExchange e, CancellationToken ct)
    {
        var msg = EnsureOut(e);

        // Propagate ContentType from In (EnsureOut only copies Body, not metadata).
        // Without this, an upstream HTML response (e.g. form_post) loses its content-type
        // and HttpConsumer falls back to the default application/json.
        msg.ContentType ??= e.In.ContentType;
        if (!msg.Headers.ContainsKey(HttpHeaders.ResponseContentType)
            && e.In.Headers.TryGetValue(HttpHeaders.ResponseContentType, out var rct))
        {
            msg.Headers[HttpHeaders.ResponseContentType] = rct;
        }

        if (msg.Body is IDictionary<string, object?> dict)
        {
            // Final HTTP serialization for OIDC/OAuth/DCR responses. Uses the locked
            // OAuth profile (RFC 6749 §5.1, UTF-8, ignore nulls) — bypasses the configurable
            // Route codec registry so user config cannot reshape the OAuth wire format.
            msg.Body = JsonSerializer.SerializeToUtf8Bytes(dict, IdentityWireProfiles.OAuthOptions);
            // Core-level content type keeps the value transport-agnostic for Rabbit/Kafka façades.
            msg.ContentType ??= IdentityWireProfiles.OAuthMediaType;
            msg.Headers.TryAdd(HttpHeaders.ResponseContentType, IdentityWireProfiles.OAuthMediaType);
        }

        // E5: echo the propagated correlation id on every response so the caller can
        // stitch its own log entries to ours. Stored as an exchange property by
        // PropagateCorrelationId at the head of every HTTP route.
        if (e.Properties.TryGetValue("identity:correlation-id", out var corrObj)
            && corrObj is string corr
            && !string.IsNullOrEmpty(corr))
        {
            msg.Headers.TryAdd("X-Correlation-Id", corr);
        }

        // Propagate ResponseCode from In if not already set on Out
        // (EnsureOut creates Out from In.Body only, not headers)
        if (!msg.Headers.ContainsKey(HttpHeaders.ResponseCode)
            && e.In.Headers.TryGetValue(HttpHeaders.ResponseCode, out var rc))
        {
            msg.Headers[HttpHeaders.ResponseCode] = rc;
        }

        // Propagate Set-Cookie from In if not already set on Out
        // (PipelineProcessor merges Out→In between steps, so headers set by earlier
        //  post-processors end up on In; EnsureOut doesn't copy them to new Out)
        if (!msg.Headers.ContainsKey("Set-Cookie")
            && e.In.Headers.TryGetValue("Set-Cookie", out var sc))
        {
            msg.Headers["Set-Cookie"] = sc;
        }

        // Propagate WWW-Authenticate (RFC 6750 §3) for protected-resource error responses.
        // AttachBearerChallengeOnError on the userinfo routes sets it on In; the merge
        // between processors only carries it forward, EnsureOut doesn't copy headers, so
        // we explicitly forward it here.
        if (!msg.Headers.ContainsKey("WWW-Authenticate")
            && e.In.Headers.TryGetValue("WWW-Authenticate", out var wa))
        {
            msg.Headers["WWW-Authenticate"] = wa;
        }

        // Propagate Location header for redirects (302)
        if (!msg.Headers.ContainsKey("Location")
            && e.In.Headers.TryGetValue("Location", out var loc))
        {
            msg.Headers["Location"] = loc;
        }

        // D1/D2: propagate Cache-Control so response caching directives set by
        // endpoint processors (Discovery, JWKS) reach the HTTP writer. The pipeline
        // merges Out→In between steps, so a header set on Out by an earlier .To()
        // lands on In by the time this post-processor runs; EnsureOut won't copy it.
        if (!msg.Headers.ContainsKey("Cache-Control")
            && e.In.Headers.TryGetValue("Cache-Control", out var cc))
        {
            msg.Headers["Cache-Control"] = cc;
        }

        // Z4 P2 (RFC 9449 §8): propagate DPoP-Nonce set by ApplyTokenResponseHandler so
        // that clients can adopt the rotated nonce on subsequent proofs. Same Out→In
        // merge concern as Cache-Control above.
        if (!msg.Headers.ContainsKey("DPoP-Nonce")
            && e.In.Headers.TryGetValue("DPoP-Nonce", out var dpopNonce))
        {
            msg.Headers["DPoP-Nonce"] = dpopNonce;
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// RFC 6749 §5.1/§5.2 — the token endpoint MUST send <c>Cache-Control: no-store</c> and
    /// <c>Pragma: no-cache</c> on every response so intermediaries never cache issued tokens.
    /// Wire this AFTER <see cref="SerializeJsonResponse"/> on the token endpoint (and the other
    /// token-bearing endpoints: PAR, introspection, revocation, device authorization). It is
    /// deliberately NOT applied to discovery/JWKS, which are cacheable by design.
    /// </summary>
    internal static Task AddNoStoreCacheHeaders(IExchange e, CancellationToken ct)
    {
        var msg = e.HasOut ? e.Out! : e.In;
        msg.Headers["Cache-Control"] = "no-store";
        msg.Headers["Pragma"] = "no-cache";
        return Task.CompletedTask;
    }

    /// <summary>
    /// Handles post-logout redirect per OIDC RP-Initiated Logout §2.
    /// If the response contains <c>post_logout_redirect_uri</c>, validates it against
    /// registered application URIs and redirects (302) only if valid.
    /// Otherwise renders a simple "logged out" HTML page.
    /// </summary>
    /// <summary>
    /// Saves post_logout_redirect_uri from body to exchange properties before To() replaces the body.
    /// </summary>
    internal static Task PreservePostLogoutRedirectUri(IExchange e, CancellationToken ct)
    {
        if (e.In.Body is IDictionary<string, object?> body
            && body.TryGetValue("post_logout_redirect_uri", out var uri)
            && uri is string s && !string.IsNullOrEmpty(s))
        {
            e.Properties["post_logout_redirect_uri"] = s;
        }
        return Task.CompletedTask;
    }

    internal static async Task HandlePostLogoutRedirect(
        IExchange e, CancellationToken ct, IdentityTransportOptions opts,
        Func<string, CancellationToken, Task<bool>>? validator)
    {
        var msg = EnsureOut(e);

        // Read redirect URI from exchange properties (preserved before To() replaced the body)
        var redirectUri = e.Properties.TryGetValue("post_logout_redirect_uri", out var uriObj)
            ? uriObj?.ToString()
            : null;

        if (!string.IsNullOrEmpty(redirectUri))
        {
            // Validate redirect URI against registered applications (open redirect protection).
            // Phase 9e: validation is now delegated to a Func passed in from the route builder
            // so this processor has zero compile-time knowledge of OpenIddict / Core types.
            // The Func is backed by BrokeredPostLogoutRedirectValidator (direct-vm broker call)
            // in .tpkg mode, or by a direct OpenIddict adapter in test-fixture mode.
            var isValid = false;
            if (validator is not null)
                isValid = await validator(redirectUri, ct).ConfigureAwait(false);

            if (isValid)
            {
                msg.Headers[HttpHeaders.ResponseCode] = 302;
                msg.Headers["Location"] = redirectUri;
                return;
            }
            // Invalid or unregistered URI — fall through to "signed out" page
        }

        // No redirect — render a "signed out" page using shared template
        var cardContent = "<h1>Signed Out</h1><p>You have been signed out successfully.</p>";
        msg.Body = IdentityPageTemplates.WrapPage("Signed Out", cardContent, opts);
        msg.Headers[HttpHeaders.ResponseContentType] = "text/html; charset=utf-8";
        msg.Headers[HttpHeaders.ResponseCode] = 200;
    }

    /// <summary>
    /// Ensures <see cref="IExchange.Out"/> exists, creating it from the In body if needed.
    /// Post-processors should always write to Out (response), not mutate In (request).
    /// </summary>
    private static IMessage EnsureOut(IExchange e)
    {
        if (e.HasOut) return e.Out!;
        e.Out = new Message(e.In.Body);
        return e.Out;
    }

    /// <summary>
    /// Post-processor for the management API controller route.
    /// Inspects the serialized JSON response body for an <c>"error"</c> field
    /// and maps it to the appropriate HTTP status code.
    /// Must be chained AFTER <c>.RedbHttpController()</c> which sets status 200.
    /// The pipeline merges controller Out→In before this step, so body is on <c>e.In.Body</c>.
    /// </summary>
    internal static Task MapManagementErrorToHttpStatus(IExchange e, CancellationToken ct)
    {
        if (e.In.Body is not byte[] json || json.Length == 0)
            return Task.CompletedTask;

        try
        {
            var reader = new Utf8JsonReader(json);

            // Only inspect root-level JSON objects (arrays = list responses, skip them)
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
                return Task.CompletedTask;

            string? error = null;

            while (reader.Read())
            {
                // Only check top-level properties (depth 1 = directly inside root object)
                if (reader.CurrentDepth == 1
                    && reader.TokenType == JsonTokenType.PropertyName
                    && reader.ValueTextEquals("error"u8))
                {
                    if (reader.Read() && reader.TokenType == JsonTokenType.String)
                        error = reader.GetString();
                    break;
                }

                // Skip nested structures entirely
                if (reader.TokenType is JsonTokenType.StartObject or JsonTokenType.StartArray)
                    reader.Skip();
            }

            if (error is null) return Task.CompletedTask;

            var statusCode = error switch
            {
                "not_found" => 404,
                "duplicate" => 409,
                "validation_error" => 400,
                "invalid_request" => 400,
                "invalid_operation" => 400,
                "invalid_password" => 400,
                "weak_password" => 400,
                "registration_disabled" => 403,
                "server_error" => 500,
                _ => 400,
            };

            // Create Out to override the pipeline's restored lastOut (which has status 200).
            // Body is already serialized byte[] JSON from the controller dispatcher.
            e.Out = new Message(e.In.Body);
            e.Out.Headers[HttpHeaders.ResponseCode] = statusCode;
            e.Out.Headers[HttpHeaders.ResponseContentType] = "application/json";
        }
        catch (JsonException)
        {
            // Not valid JSON — skip status mapping
        }

        return Task.CompletedTask;
    }
}
