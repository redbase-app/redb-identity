using redb.Identity.Contracts.Validation;
using redb.Route.Abstractions;
using redb.Route.Core;

namespace redb.Identity.Http.Controllers;

/// <summary>
/// SCIM controller base with a Forward() that correctly returns null for deletions
/// and propagates SCIM-specific response hints (status code, location).
/// </summary>
public abstract class ScimControllerBase : IdentityControllerBase
{
    /// <summary>
    /// SCIM-aware DataAnnotations validation. Returns <c>null</c> if the DTO is valid;
    /// otherwise a populated <see cref="redb.Identity.Contracts.Scim.ScimError"/>
    /// with <c>status=400</c> and <c>scimType=invalidValue</c>, which the SCIM
    /// status mapper turns into HTTP 400 (E6 / RFC 7644 §3.12).
    /// </summary>
    protected static new object? ValidateRequest(object? request)
        => ScimRequestValidator.Validate(request);

    /// <summary>
    /// Forwards an operation to a direct-vm endpoint, returning the Out.Body directly.
    /// Unlike the base class, null Out.Body is returned as null (enabling 204 for DELETE).
    /// Also propagates scim.* headers to the HTTP exchange for post-processor handling.
    /// </summary>
    protected new async Task<object?> Forward(string endpointUri, string operation, object? body = null)
    {
        var endpoint = Context.GetEndpoint(endpointUri);

        var msg = new Message();
        msg.Headers["operation"] = operation;
        if (body is not null)
            msg.Body = body;

        // M1: Pass base URL to processor for absolute Meta.Location URIs
        var httpUrl = Exchange.In.GetHeader<string>("redbHttp.Url");
        if (httpUrl is not null && Uri.TryCreate(httpUrl, UriKind.Absolute, out var uri))
            msg.Headers["scim.BaseUrl"] = $"{uri.Scheme}://{uri.Authority}";

        // Pass If-Match header for ETag precondition checks
        var ifMatch = Exchange.In.GetHeader<string>("If-Match");
        if (!string.IsNullOrEmpty(ifMatch))
            msg.Headers["scim.IfMatch"] = ifMatch;

        // E2 — propagate Idempotency-Key + HTTP method into the inner direct-vm exchange.
        var idemKey = Exchange.In.GetHeader<string>("Idempotency-Key")
                      ?? Exchange.In.GetHeader<string>("idempotency-key");
        if (!string.IsNullOrEmpty(idemKey))
            msg.Headers["Idempotency-Key"] = idemKey;
        var httpMethod = Exchange.In.GetHeader<string>("redbHttp.Method");
        if (!string.IsNullOrEmpty(httpMethod))
            msg.Headers["redbHttp.Method"] = httpMethod;

        // CreateChild gives the inner exchange its own fresh DI scope inherited from the
        // outer HTTP exchange's scope factory. Without this the inner Exchange has a null
        // ServiceProvider and SCIM/identity processors fall back to the captive root
        // IRedbService — single connection serialising all concurrent HTTP requests and
        // surfacing as NpgsqlOperationInProgressException under load. Falls back to a
        // bare Exchange when the outer Exchange is unavailable (unit tests).
        var exchange = Exchange?.CreateChild(msg) ?? new Exchange(msg);
        exchange.Pattern = ExchangePattern.InOut;
        var producer = endpoint.CreateProducer();
        try
        {
            await producer.Process(exchange).ConfigureAwait(false);

            // B2 — propagate transport-level response meta (redbHttp.ResponseCode, Content-Type,
            // Location, ETag, ...) from the inner exchange to the outer HTTP exchange so inner
            // OnException handlers actually affect the HTTP status. Must run before we copy the
            // SCIM-specific hints below (so domain hints can override transport defaults).
            PropagateInnerResponse(exchange);

            // Identity pipeline convention: business processors write the response into
            // exchange.In.Body (see memory note identity-response-body-convention.md);
            // PipelineProcessor never synthesises Out from In (Camel-compliant). Read from
            // Out when present, else fall back to In — applies to body and to all hint headers.
            var responseSource = exchange.Out ?? exchange.In;

            // Propagate SCIM response hints to HTTP exchange for post-processors
            if (responseSource is not null)
            {
                if (responseSource.Headers.TryGetValue("scim.ResponseCode", out var rc))
                    Exchange.In.Headers["scim.ResponseCode"] = rc;
                if (responseSource.Headers.TryGetValue("scim.Location", out var loc))
                {
                    // Make Location absolute if base URL is available
                    msg.Headers.TryGetValue("scim.BaseUrl", out var baseUrlObj);
                    var baseUrl = baseUrlObj?.ToString() ?? "";
                    var absLoc = loc?.ToString()?.StartsWith("/") == true ? $"{baseUrl}{loc}" : loc;
                    Exchange.In.Headers["scim.Location"] = absLoc;
                }
                if (responseSource.Headers.TryGetValue("scim.ETag", out var etag))
                    Exchange.In.Headers["scim.ETag"] = etag;
                if (responseSource.Headers.TryGetValue("Idempotency-Replayed", out var replayed))
                    Exchange.In.Headers["Idempotency-Replayed"] = replayed;
            }

            // SCIM DELETE → 204 No Content: the delete processor signals via scim.ResponseCode=204
            // and leaves no real response body. When Out is absent, In.Body still holds the
            // original request payload we set via msg.Body=body above, which must NOT be echoed.
            if (responseSource is not null
                && responseSource.Headers.TryGetValue("scim.ResponseCode", out var rcCheck)
                && rcCheck is int code && (code == 204 || code == 304))
                return null;

            // Same protection for the general "no Out produced" case: if In.Body is still the
            // request payload we passed in (i.e. no processor overwrote it), don't echo it back.
            if (exchange.Out is null && ReferenceEquals(exchange.In.Body, body))
                return null;

            return responseSource?.Body;
        }
        finally
        {
            // CRITICAL: dispose the inner exchange so its DI scope (and the scoped
            // NpgsqlConnection within) is released back to the pool. Without this each
            // SCIM HTTP call leaks one connection until MaxPoolSize is hit and subsequent
            // calls 503 with NpgsqlException("connection pool exhausted").
            await exchange.DisposeAsync().ConfigureAwait(false);
        }
    }
}
