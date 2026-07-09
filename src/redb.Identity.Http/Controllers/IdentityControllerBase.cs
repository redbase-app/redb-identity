using redb.Identity.Contracts.Routes;
using redb.Identity.Contracts.Validation;
using redb.Route.Abstractions;
using redb.Route.Controllers;
using redb.Route.Core;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// Base controller for Identity management API. Forwards operations to
/// <c>direct-vm://identity-manage-*</c> routes via the route context,
/// preserving WireTap (event dispatch), retry, and error handling.
/// </summary>
public abstract class IdentityControllerBase : RedbController
{
    /// <summary>
    /// Parses a route ID parameter as either a numeric or string key.
    /// Numeric IDs are stored under <paramref name="numericKey"/>,
    /// string IDs under <paramref name="stringKey"/>.
    /// </summary>
    protected static object ParseIdBody(string id, string numericKey = "id", string stringKey = "id") =>
        long.TryParse(id, out var numericId)
            ? new Dictionary<string, object> { [numericKey] = numericId }
            : new Dictionary<string, object> { [stringKey] = id };

    /// <summary>
    /// Runs DataAnnotations validation on the request DTO.
    /// Returns <c>null</c> if valid; otherwise a problem object the controller method
    /// can return as-is — <see cref="redb.Identity.Http.Processors.HttpIdentityProcessors"/>
    /// maps the resulting <c>error = "invalid_request"</c> body to HTTP 400 (E6 / D5).
    /// </summary>
    protected static object? ValidateRequest(object? request) => RequestValidator.Validate(request);

    /// <summary>
    /// Sends an operation to a <c>direct-vm://identity-manage-*</c> route,
    /// preserving route-level cross-cutting concerns (WireTap event dispatch,
    /// OnException retry, error handling). Returns the response body.
    /// <para>
    /// B8: propagates the authenticated caller's subject and granted scopes from the outer
    /// HTTP exchange (set by <c>ManagementBearerAuthProcessor</c>) into the inner direct-vm
    /// exchange so that <c>RequireSelfOrAdminProcessor</c> can enforce self-vs-admin
    /// authorization downstream.
    /// </para>
    /// </summary>
    protected async Task<object?> Forward(string endpointUri, string operation, object? body = null)
    {
        var endpoint = Context.GetEndpoint(endpointUri);

        var msg = new Message();
        msg.Headers["operation"] = operation;
        if (body is not null)
            msg.Body = body;

        // E2 — propagate the Idempotency-Key header (RFC TBD, de-facto standard) from the
        // outer HTTP exchange into the inner direct-vm exchange so that
        // IdempotencyProcessor on the route can short-circuit duplicate retries with the
        // cached response. Also forward the HTTP method for audit metadata.
        if (Exchange?.In is { } httpIn)
        {
            var idemKey = httpIn.GetHeader<string>("Idempotency-Key")
                          ?? httpIn.GetHeader<string>("idempotency-key");
            if (!string.IsNullOrEmpty(idemKey))
                msg.Headers["Idempotency-Key"] = idemKey;
            var method = httpIn.GetHeader<string>("redbHttp.Method");
            if (!string.IsNullOrEmpty(method))
                msg.Headers["redbHttp.Method"] = method;
        }

        // CreateChild gives the inner exchange its own fresh DI scope inherited from the
        // outer HTTP exchange's scope factory. Without this the inner Exchange has a null
        // ServiceProvider and identity processors fall back to the captive root
        // IRedbService — single connection serialising all concurrent HTTP requests and
        // surfacing as NpgsqlOperationInProgressException under load. Falls back to a
        // bare Exchange when the outer Exchange is unavailable (unit tests).
        var exchange = Exchange?.CreateChild(msg) ?? new Exchange(msg);
        exchange.Pattern = ExchangePattern.InOut;

        // Propagate auth context (B8 — RequireSelfOrAdminProcessor depends on these).
        if (Exchange?.Properties is { } outerProps)
        {
            if (outerProps.TryGetValue("identity:management-principal", out var principal))
                exchange.Properties["identity:management-principal"] = principal;
            if (outerProps.TryGetValue("identity:management-subject", out var subject))
                exchange.Properties["identity:management-subject"] = subject;
            if (outerProps.TryGetValue("identity:management-scopes", out var scopes))
                exchange.Properties["identity:management-scopes"] = scopes;
            // H3-SSO: the "sid" claim from the caller's access token (optional — only set
            // for OIDC session-backed tokens). Required by MeSessionsProcessor's
            // revoke-current operation.
            if (outerProps.TryGetValue("identity:management-sid", out var sid))
                exchange.Properties["identity:management-sid"] = sid;
        }

        var producer = endpoint.CreateProducer();
        try
        {
            await producer.Process(exchange).ConfigureAwait(false);

            // E2 — surface the Idempotency-Replayed marker to the HTTP response so callers can
            // tell when they were served from cache (debugging / metrics). Read from Out ?? In
            // (Identity convention — see identity-response-body-convention.md).
            var idemSrc = exchange.Out ?? exchange.In;
            if (idemSrc?.Headers.TryGetValue("Idempotency-Replayed", out var replayed) == true
                && Exchange?.In is { } outHttp)
            {
                outHttp.Headers["Idempotency-Replayed"] = replayed;
            }

            // B2 — propagate response-meta from the inner direct-vm exchange to the outer HTTP
            // exchange. Without this, inner OnException handlers (which set e.g.
            // redbHttp.ResponseCode=503 on inner.Out) are silently discarded and the caller
            // sees HTTP 200 with an error body — a critical contract violation.
            PropagateInnerResponse(exchange);

            return exchange.Out?.Body ?? exchange.In.Body;
        }
        finally
        {
            // CRITICAL: dispose the inner exchange so its DI scope (and the scoped
            // NpgsqlConnection within) is released back to the pool. Without this each
            // SCIM/management HTTP call leaks one connection until MaxPoolSize is hit
            // and subsequent calls 503 with NpgsqlException("connection pool exhausted").
            await exchange.DisposeAsync().ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Mirrors response meta (HTTP status, content type, error envelopes) from the inner
    /// direct-vm exchange to the outer HTTP exchange's Out message. The kernel
    /// <c>HttpControllerDispatcher.WriteResult</c> respects pre-set headers, so after this
    /// call the dispatcher will not clobber the response code/content-type carried by inner
    /// route handlers (OnException, explicit redirects, 202 Accepted, etc.).
    /// </summary>
    protected void PropagateInnerResponse(IExchange innerExchange)
    {
        if (Exchange is null) return;
        // Identity pipeline convention: business processors write the response into
        // exchange.In (see identity-response-body-convention.md). PipelineProcessor is
        // Camel-compliant and never synthesises Out from In, so transport-meta headers
        // (redbHttp.ResponseCode, Location, ETag, Idempotency-Replayed, ...) may live on
        // either side. Reading from Out ?? In keeps the whitelist below universal.
        var innerSrc = innerExchange.Out ?? innerExchange.In;
        if (innerSrc is null) return;

        Exchange.Out ??= Exchange.In.Clone();
        var outerOut = Exchange.Out;

        // Headers that describe the HTTP response envelope and must survive across the
        // facade boundary. This list intentionally covers only transport-level meta; domain
        // headers (scim.*) are handled by domain-specific Forward overrides where needed.
        CopyHeader(innerSrc, outerOut, "redbHttp.ResponseCode");
        CopyHeader(innerSrc, outerOut, "redbHttp.ResponseContentType");
        CopyHeader(innerSrc, outerOut, "Content-Type");
        CopyHeader(innerSrc, outerOut, "Location");
        CopyHeader(innerSrc, outerOut, "ETag");
        CopyHeader(innerSrc, outerOut, "Cache-Control");
        CopyHeader(innerSrc, outerOut, "Retry-After");
    }

    private static void CopyHeader(IMessage src, IMessage dst, string key)
    {
        if (src.Headers.TryGetValue(key, out var val) && val is not null
            && !dst.Headers.ContainsKey(key))
        {
            dst.Headers[key] = val;
        }
    }
}
