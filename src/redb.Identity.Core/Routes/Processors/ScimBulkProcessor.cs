using System.Text.Json;
using redb.Identity.Contracts.Scim;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// SCIM 2.0 Bulk endpoint processor (RFC 7644 §3.7).
/// <para>
/// Accepts a <see cref="ScimBulkRequest"/> with up to <c>maxOperations</c> operations,
/// dispatches each operation to the corresponding internal direct-vm endpoint
/// (<c>identity-scim-users</c> / <c>identity-scim-groups</c>) and aggregates the
/// per-operation results into a <see cref="ScimBulkResponse"/>.
/// </para>
/// <para>
/// Per RFC §3.7.3 partial success is allowed; each inner op runs in its own redb
/// transaction (the inner SCIM routes are <c>WithIdempotentTx</c>). The
/// <c>failOnErrors</c> attribute caps the error stream — once exceeded the bulk
/// loop terminates and the partial response is returned.
/// </para>
/// <para>
/// Forward bulkId references (RFC §3.7.2) are resolved client-side by scanning
/// each operation's <c>data</c> JSON for <c>"bulkId:&lt;key&gt;"</c> string values
/// and substituting the location of a previously-created resource. References
/// to a not-yet-created bulkId fail the operation with status 409.
/// </para>
/// </summary>
internal sealed class ScimBulkProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly int _maxOperations;
    private readonly int _maxPayloadSize;

    public ScimBulkProcessor(IRouteContext context, int maxOperations, int maxPayloadSize)
    {
        _context = context;
        _maxOperations = maxOperations <= 0 ? 1000 : maxOperations;
        _maxPayloadSize = maxPayloadSize <= 0 ? 1_048_576 : maxPayloadSize;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var request = exchange.In.Body as ScimBulkRequest;
        if (request is null)
        {
            SetScimError(exchange, 400, null, "Invalid SCIM bulk request body");
            return;
        }

        if (request.Operations.Count == 0)
        {
            SetScimError(exchange, 400, null, "Bulk request must contain at least one operation");
            return;
        }

        if (request.Operations.Count > _maxOperations)
        {
            SetScimError(exchange, 413, "tooLarge",
                $"Bulk request exceeds maxOperations limit of {_maxOperations}");
            return;
        }

        var baseUrl = exchange.In.GetHeader<string>("scim.BaseUrl") ?? string.Empty;
        var ifMatch = exchange.In.GetHeader<string>("scim.IfMatch");

        // Map of bulkId → server-assigned location for forward-reference resolution (§3.7.2).
        var bulkIdLocations = new Dictionary<string, string>(StringComparer.Ordinal);

        var response = new ScimBulkResponse();
        var errorCount = 0;
        var failOnErrors = request.FailOnErrors > 0 ? request.FailOnErrors : int.MaxValue;
        var processedCount = 0;
        var successCount = 0;

        foreach (var op in request.Operations)
        {
            if (errorCount >= failOnErrors) break;

            var opResponse = new ScimBulkOperationResponse
            {
                Method = op.Method,
                BulkId = op.BulkId
            };

            try
            {
                var routed = await DispatchOperationAsync(exchange, op, baseUrl, ifMatch, bulkIdLocations, ct);
                opResponse.Status = routed.Status;
                opResponse.Location = routed.Location;
                opResponse.Response = routed.Response;
                if (!string.IsNullOrEmpty(op.BulkId) && !string.IsNullOrEmpty(routed.Location))
                    bulkIdLocations[op.BulkId!] = routed.Location!;

                if (IsSuccessStatus(routed.Status))
                    successCount++;
                else
                    errorCount++;
            }
            catch (Exception ex)
            {
                errorCount++;
                opResponse.Status = "500";
                opResponse.Response = SerializeError(new ScimError
                {
                    Status = "500",
                    Detail = ex.Message
                });
            }

            response.Operations.Add(opResponse);
            processedCount++;
        }

        SetResult(exchange, response);
        exchange.Out!.Headers["scim.ResponseCode"] = 200;

        // Audit: emit a single rolled-up event for the whole bulk request.
        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ScimBulkProcessed;
        exchange.Properties["identity-event-data"] = new
        {
            Operations = processedCount,
            Succeeded = successCount,
            Failed = errorCount,
            request.FailOnErrors
        };
    }

    private async Task<DispatchResult> DispatchOperationAsync(
        IExchange parent,
        ScimBulkOperation op,
        string baseUrl,
        string? ifMatch,
        IReadOnlyDictionary<string, string> bulkIdLocations,
        CancellationToken ct)
    {
        if (string.IsNullOrEmpty(op.Method) || string.IsNullOrEmpty(op.Path))
            return DispatchResult.Error(400, "invalidValue", "Bulk operation requires 'method' and 'path'");

        if (!TryParsePath(op.Path, out var resourceType, out var resourceId))
            return DispatchResult.Error(400, "invalidPath",
                $"Unsupported bulk path '{op.Path}'. Only /Users[/{{id}}] and /Groups[/{{id}}] are supported.");

        var endpointUri = resourceType == "Users"
            ? IdentityEndpoints.ScimUsers
            : IdentityEndpoints.ScimGroups;

        // Resolve forward bulkId references inside the data JSON before deserialization.
        var resolvedData = op.Data;
        if (op.Data is { } d)
        {
            var (resolved, missingRef) = ResolveBulkIds(d, bulkIdLocations);
            if (missingRef is not null)
                return DispatchResult.Error(409, "invalidValue",
                    $"Bulk operation references unresolved bulkId '{missingRef}'");
            resolvedData = resolved;
        }

        // Build the body shape expected by the inner direct-vm processor.
        var method = op.Method.ToUpperInvariant();
        object? body;
        string operationName;

        switch (method)
        {
            case "POST":
                if (!string.IsNullOrEmpty(resourceId))
                    return DispatchResult.Error(400, "invalidPath", "POST requires a collection path");
                if (resolvedData is not { } pd)
                    return DispatchResult.Error(400, "invalidValue", "POST requires a 'data' payload");
                body = resourceType == "Users"
                    ? (object?)pd.Deserialize<ScimUser>()
                    : pd.Deserialize<ScimGroup>();
                if (body is null)
                    return DispatchResult.Error(400, "invalidValue", "Invalid 'data' payload");
                operationName = "create";
                break;

            case "PUT":
                if (string.IsNullOrEmpty(resourceId))
                    return DispatchResult.Error(400, "invalidPath", "PUT requires a resource path");
                if (resolvedData is not { } putData)
                    return DispatchResult.Error(400, "invalidValue", "PUT requires a 'data' payload");
                if (resourceType == "Users")
                {
                    var u = putData.Deserialize<ScimUser>();
                    if (u is null) return DispatchResult.Error(400, "invalidValue", "Invalid 'data' payload");
                    u.Id = resourceId;
                    body = u;
                }
                else
                {
                    var g = putData.Deserialize<ScimGroup>();
                    if (g is null) return DispatchResult.Error(400, "invalidValue", "Invalid 'data' payload");
                    g.Id = resourceId;
                    body = g;
                }
                operationName = "replace";
                break;

            case "PATCH":
                if (string.IsNullOrEmpty(resourceId))
                    return DispatchResult.Error(400, "invalidPath", "PATCH requires a resource path");
                if (resolvedData is not { } patchData)
                    return DispatchResult.Error(400, "invalidValue", "PATCH requires a 'data' payload");
                var patch = patchData.Deserialize<ScimPatchRequest>();
                if (patch is null)
                    return DispatchResult.Error(400, "invalidValue", "Invalid PatchOp payload");
                body = new Dictionary<string, object?>
                {
                    ["id"] = resourceId,
                    ["patch"] = patch
                };
                operationName = "patch";
                break;

            case "DELETE":
                if (string.IsNullOrEmpty(resourceId))
                    return DispatchResult.Error(400, "invalidPath", "DELETE requires a resource path");
                body = new Dictionary<string, object?> { ["id"] = resourceId };
                operationName = "delete";
                break;

            default:
                return DispatchResult.Error(400, "invalidValue", $"Unsupported HTTP method '{op.Method}'");
        }

        var endpoint = _context.GetEndpoint(endpointUri);
        var msg = new Message();
        msg.Headers["operation"] = operationName;
        msg.Body = body;
        if (!string.IsNullOrEmpty(baseUrl)) msg.Headers["scim.BaseUrl"] = baseUrl;
        if (!string.IsNullOrEmpty(ifMatch)) msg.Headers["scim.IfMatch"] = ifMatch!;

        // CreateChild gives the inner exchange its own fresh DI scope (per-op IRedbService),
        // so concurrent bulk inner ops don't share a connection. Without this the inner
        // Exchange has a null ServiceProvider and the SCIM processors fall back to the
        // captive root-provider IRedbService — single connection for all inner ops.
        var inner = parent.CreateChild(msg);
        inner.Pattern = ExchangePattern.InOut;
        var producer = endpoint.CreateProducer();
        try
        {
            await producer.Process(inner).ConfigureAwait(false);

            var status = ExtractStatus(inner, operationName);
            var location = ExtractLocation(inner, baseUrl);
            var responseBody = ExtractResponseBody(inner, status);

            return new DispatchResult(status, location, responseBody);
        }
        finally
        {
            // CRITICAL: dispose the per-op inner exchange so its DI scope (and the scoped
            // NpgsqlConnection) is released back to the pool. Without this each bulk op
            // leaks one connection — quickly exhausts MaxPoolSize for large bulk batches.
            await inner.DisposeAsync().ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Walks a JSON tree and replaces any string of the form <c>"bulkId:&lt;key&gt;"</c>
    /// with the corresponding location from <paramref name="bulkIdLocations"/>.
    /// Returns the missing bulkId when an unresolved reference is encountered.
    /// </summary>
    private static (JsonElement Resolved, string? MissingRef) ResolveBulkIds(
        JsonElement source, IReadOnlyDictionary<string, string> bulkIdLocations)
    {
        if (!ContainsBulkIdRef(source))
            return (source, null);

        using var doc = JsonDocument.Parse(source.GetRawText());
        var buffer = new System.IO.MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            string? missing = null;
            WriteRewritten(doc.RootElement, writer, bulkIdLocations, ref missing);
            if (missing is not null) return (source, missing);
        }
        buffer.Position = 0;
        using var resolvedDoc = JsonDocument.Parse(buffer);
        return (resolvedDoc.RootElement.Clone(), null);
    }

    private static bool ContainsBulkIdRef(JsonElement el)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.String:
                var s = el.GetString();
                return s is not null && s.StartsWith("bulkId:", StringComparison.Ordinal);
            case JsonValueKind.Object:
                foreach (var p in el.EnumerateObject())
                    if (ContainsBulkIdRef(p.Value)) return true;
                return false;
            case JsonValueKind.Array:
                foreach (var v in el.EnumerateArray())
                    if (ContainsBulkIdRef(v)) return true;
                return false;
            default:
                return false;
        }
    }

    private static void WriteRewritten(
        JsonElement el,
        Utf8JsonWriter writer,
        IReadOnlyDictionary<string, string> bulkIdLocations,
        ref string? missing)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var p in el.EnumerateObject())
                {
                    writer.WritePropertyName(p.Name);
                    WriteRewritten(p.Value, writer, bulkIdLocations, ref missing);
                    if (missing is not null) return;
                }
                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var v in el.EnumerateArray())
                {
                    WriteRewritten(v, writer, bulkIdLocations, ref missing);
                    if (missing is not null) return;
                }
                writer.WriteEndArray();
                break;
            case JsonValueKind.String:
                var s = el.GetString();
                if (s is not null && s.StartsWith("bulkId:", StringComparison.Ordinal))
                {
                    var key = s.Substring("bulkId:".Length);
                    if (!bulkIdLocations.TryGetValue(key, out var loc))
                    {
                        missing = key;
                        return;
                    }
                    writer.WriteStringValue(loc);
                }
                else
                {
                    writer.WriteStringValue(s);
                }
                break;
            default:
                el.WriteTo(writer);
                break;
        }
    }

    private static bool TryParsePath(string path, out string resourceType, out string? resourceId)
    {
        resourceType = string.Empty;
        resourceId = null;
        if (string.IsNullOrEmpty(path) || path[0] != '/') return false;
        var parts = path.TrimStart('/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0 || parts.Length > 2) return false;
        if (!string.Equals(parts[0], "Users", StringComparison.Ordinal)
            && !string.Equals(parts[0], "Groups", StringComparison.Ordinal))
            return false;
        resourceType = parts[0];
        if (parts.Length == 2) resourceId = parts[1];
        return true;
    }

    private static int ExtractStatus(IExchange inner, string operationName)
    {
        // Camel canon: response = Out ?? In. The terminal pipeline step (e.g. WireTap)
        // may have caused the merge to clear Out and leave the business response on In.
        var src = inner.Out ?? inner.In;
        if (src?.Headers.TryGetValue("scim.ResponseCode", out var rc) == true
            && rc is int code) return code;

        // Defaults if the inner processor didn't set scim.ResponseCode.
        if (src?.Body is ScimError err && int.TryParse(err.Status, out var es)) return es;
        return operationName switch
        {
            "create" => 201,
            "delete" => 204,
            _ => 200
        };
    }

    private static string? ExtractLocation(IExchange inner, string baseUrl)
    {
        var src = inner.Out ?? inner.In;
        if (src?.Headers.TryGetValue("scim.Location", out var loc) == true)
        {
            var s = loc?.ToString();
            if (string.IsNullOrEmpty(s)) return null;
            if (s.StartsWith("/", StringComparison.Ordinal) && !string.IsNullOrEmpty(baseUrl))
                return baseUrl + s;
            return s;
        }
        return null;
    }

    private static JsonElement? ExtractResponseBody(IExchange inner, int status)
    {
        var body = (inner.Out ?? inner.In)?.Body;
        if (body is null) return null;
        // Per RFC 7644 §3.7.3, the per-op `response` field is REQUIRED for errors and
        // OPTIONAL for success. We include it for errors and omit on plain success
        // (clients can dereference Location for the created resource).
        if (status >= 400)
            return SerializeError(body as ScimError ?? new ScimError { Status = status.ToString() });
        return null;
    }

    private static JsonElement SerializeError(object body)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(body);
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    private static bool IsSuccessStatus(string status)
        => int.TryParse(status, out var code) && code is >= 200 and < 300;

    private static void SetResult(IExchange exchange, object body)
    {
        exchange.Out ??= new Message();
        exchange.Out.Body = body;
    }

    private static void SetScimError(IExchange exchange, int status, string? scimType, string detail)
    {
        exchange.Out ??= new Message();
        exchange.Out.Body = new ScimError
        {
            Status = status.ToString(),
            ScimType = scimType,
            Detail = detail
        };
        exchange.Out.Headers["scim.ResponseCode"] = status;
    }

    private readonly record struct DispatchResult(int StatusCode, string? Location, JsonElement? Response)
    {
        public string Status => StatusCode.ToString();

        public static DispatchResult Error(int status, string? scimType, string detail)
        {
            var json = JsonSerializer.SerializeToUtf8Bytes(new ScimError
            {
                Status = status.ToString(),
                ScimType = scimType,
                Detail = detail
            });
            using var doc = JsonDocument.Parse(json);
            return new DispatchResult(status, null, doc.RootElement.Clone());
        }
    }
}
