using System.Text.Json;
using redb.Identity.Contracts.Scim;
using redb.Identity.Contracts.Serialization;
using redb.Route.Abstractions;

namespace redb.Identity.Http.Processors;

/// <summary>
/// SCIM-specific HTTP processors for <c>/scim/v2/*</c> routes.
/// Handles error-to-status mapping, content type, and response serialization.
/// </summary>
internal static class ScimHttpProcessors
{
    /// <summary>
    /// Maps SCIM response body to appropriate HTTP status codes.
    /// Runs AFTER RedbHttpController (which serializes to byte[] and sets 200),
    /// so must parse the serialized JSON to detect ScimError responses.
    /// Also handles custom scim.ResponseCode/Location headers set by processors.
    /// </summary>
    internal static Task MapScimResponseToHttpStatus(IExchange exchange, CancellationToken ct)
    {
        var msg = exchange.HasOut ? exchange.Out! : exchange.In;
        var body = msg.Body;

        // Check for processor-set custom response code (e.g. 201 Created)
        if (exchange.In.Headers.TryGetValue("scim.ResponseCode", out var customCode) && customCode is int code)
        {
            msg.Headers["redbHttp.ResponseCode"] = code;
            if (exchange.In.Headers.TryGetValue("scim.Location", out var loc) && loc is string location)
                msg.Headers["Location"] = location;
            if (exchange.In.Headers.TryGetValue("scim.ETag", out var etagCustom) && etagCustom is string etagVal)
                msg.Headers["ETag"] = etagVal;
            if (!exchange.HasOut)
                exchange.Out = msg;
            return Task.CompletedTask;
        }

        // RedbHttpController serializes results to byte[]; parse to detect ScimError
        if (body is byte[] jsonBytes && jsonBytes.Length > 2)
        {
            try
            {
                using var doc = JsonDocument.Parse(jsonBytes);
                if (doc.RootElement.TryGetProperty("status", out var statusEl)
                    && doc.RootElement.TryGetProperty("schemas", out _))
                {
                    var statusStr = statusEl.GetString();
                    if (statusStr is not null && int.TryParse(statusStr, out var errCode) && errCode >= 400)
                    {
                        msg.Headers["redbHttp.ResponseCode"] = errCode;
                        // Pipeline merges Out→In between steps and restores lastOut at the end.
                        // If we only set the header on In (post-merge), lastOut retains the
                        // original 200 from WriteResult. Force-set Out so Pipeline tracks our override.
                        if (!exchange.HasOut)
                            exchange.Out = msg;
                    }
                }
            }
            catch (JsonException) { /* not valid JSON — leave default status */ }
        }
        else if (body is ScimError err && int.TryParse(err.Status, out var status))
        {
            msg.Headers["redbHttp.ResponseCode"] = status;
            if (!exchange.HasOut)
                exchange.Out = msg;
        }

        // Propagate ETag header for normal (200 OK) responses.
        // Must set exchange.Out so PipelineProcessor captures it as lastOut;
        // otherwise the restored Out from RedbHttpController won't have the ETag.
        if (exchange.In.Headers.TryGetValue("scim.ETag", out var etag) && etag is string etagStr
            && !msg.Headers.ContainsKey("ETag"))
        {
            msg.Headers["ETag"] = etagStr;
            if (!exchange.HasOut)
                exchange.Out = msg;
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Sets <c>Content-Type: application/scim+json</c> on the response
    /// and serializes the body to JSON if it's not already a string/byte[].
    /// </summary>
    internal static Task SerializeScimJsonResponse(IExchange exchange, CancellationToken ct)
    {
        var msg = exchange.HasOut ? exchange.Out! : exchange.In;
        // Set the transport-agnostic Message.ContentType so non-HTTP consumers
        // (RabbitMQProducer, Kafka, …) carry the SCIM media type natively.
        // The HTTP header mirror is kept for HttpConsumer override semantics.
        msg.ContentType = ScimConstants.MediaType;
        msg.Headers["redbHttp.ResponseContentType"] = ScimConstants.MediaType;

        if (msg.Body is not null and not string and not byte[])
        {
            // Go through the IMessageSerializer facade rather than the raw static options
            // so the wire format is observably identical to what external callers get
            // when they resolve "application/scim+json" from IDataFormatRegistry.
            // Serialize() returns byte[]; HttpProducer accepts that as payload.
            // SCIM wire serialization (RFC 7644 §3) — locked options live in Contracts so
            // the HTTP facade can serialize without taking a project-reference on Core.
            msg.Body = JsonSerializer.SerializeToUtf8Bytes(msg.Body, IdentityWireProfiles.ScimOptions);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Strips the SCIM base path prefix (<c>/scim/v2</c>) from the request path
    /// so that <see cref="redb.Route.Controllers.ControllerRegistry"/> dispatch
    /// sees controller-relative paths like <c>/Users/123</c>.
    /// </summary>
    internal static Task StripScimPrefix(IExchange exchange, CancellationToken ct)
    {
        var path = exchange.In.GetHeader<string>("redbHttp.Path");
        if (path is not null)
        {
            const string prefix = "/scim/v2";
            if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                exchange.In.Headers["redbHttp.Path"] = path[prefix.Length..];
        }
        return Task.CompletedTask;
    }
}
