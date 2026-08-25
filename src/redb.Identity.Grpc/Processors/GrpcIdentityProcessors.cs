using System.Diagnostics;
using System.Globalization;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Text.Json;
using Google.Protobuf;
using IMessage = Google.Protobuf.IMessage;
using RouteMessage = redb.Route.Abstractions.IMessage;
using Grpc.Core;
using redb.Identity.Contracts.Routes;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.Grpc;

namespace redb.Identity.Grpc.Processors;

/// <summary>
/// Translation steps between the gRPC wire and the <c>direct-vm://identity-*</c> boundary. The
/// counterpart of <c>HttpIdentityProcessors</c> in the HTTP facade, and deliberately the same shape: one
/// small step per concern, wired in order on the route.
/// </summary>
internal static class GrpcIdentityProcessors
{
    /// <summary>
    /// Parses the protobuf request and hands the boundary the parameter dictionary it expects.
    /// <para>
    /// Client credentials need no special step here: when the caller puts <c>client_id</c> /
    /// <c>client_secret</c> in the message they arrive as parameters, and when it sends
    /// <c>authorization: Basic</c> metadata instead, the connector copies that header onto the exchange
    /// and Core's own <c>BasicAuthHelper</c> reads it. Same for a Bearer token on userinfo. Duplicating
    /// that extraction in the facade would create a second, divergent source of truth.
    /// </para>
    /// </summary>
    public static Func<IExchange, CancellationToken, Task> MapRequest<TRequest>(MessageParser<TRequest> parser)
        where TRequest : IMessage<TRequest>
    {
        ArgumentNullException.ThrowIfNull(parser);

        return (exchange, _) =>
        {
            var payload = exchange.In.Body as byte[] ?? [];

            TRequest request;
            try
            {
                request = parser.ParseFrom(payload);
            }
            catch (InvalidProtocolBufferException ex)
            {
                // A malformed message is the caller's error, not ours. Answered by status rather than by
                // throwing — see Reject for why a throw would not survive.
                return Reject(exchange, StatusCode.InvalidArgument,
                    $"Malformed {typeof(TRequest).Name}: {ex.Message}");
            }

            exchange.In.Body = IdentityGrpcCodec.ToParameters(request);
            return Task.CompletedTask;
        };
    }

    /// <summary>
    /// Encodes the boundary's answer into the response message. Fields the contract names are filled by
    /// name; everything else lands in <paramref name="overflowField"/> rather than being dropped.
    /// </summary>
    public static Func<IExchange, CancellationToken, Task> MapResponse<TResponse>(string overflowField)
        where TResponse : IMessage<TResponse>, new()
    {
        return (exchange, _) =>
        {
            var response = new TResponse();

            if (ReadAnswer(exchange) is { } answer)
                IdentityGrpcCodec.Populate(response, answer, overflowField);

            Emit(exchange, response);
            return Task.CompletedTask;
        };
    }

    /// <summary>
    /// Encodes an answer that is one document — discovery and JWKS. The document is passed through
    /// verbatim: it advertises the server's HTTP addresses, and those are the real ones.
    /// </summary>
    public static Func<IExchange, CancellationToken, Task> MapDocumentResponse<TResponse>(string field)
        where TResponse : IMessage<TResponse>, new()
    {
        return (exchange, _) =>
        {
            var response = new TResponse();

            if (ReadAnswer(exchange) is { } answer)
                IdentityGrpcCodec.PopulateDocument(response, answer, field);

            Emit(exchange, response);
            return Task.CompletedTask;
        };
    }

    /// <summary>Exchange property Core and the HTTP facade both use for the correlation id.</summary>
    private const string CorrelationProperty = "identity:correlation-id";

    /// <summary>Metadata / header key carrying the correlation id, same spelling as the HTTP facade.</summary>
    private const string CorrelationHeader = "X-Correlation-Id";

    /// <summary>
    /// Propagates a correlation id across the gRPC ↔ direct-vm boundary: takes the caller's when it sent
    /// one, otherwise derives it from the ambient W3C trace id, and echoes it back in a trailer so the
    /// caller can stitch its logs to ours. Mirrors <c>HttpIdentityProcessors.PropagateCorrelationId</c>.
    /// </summary>
    public static Task PropagateCorrelationId(IExchange exchange, CancellationToken ct)
    {
        var correlationId = exchange.In.GetHeader<string>(CorrelationHeader);

        if (string.IsNullOrWhiteSpace(correlationId))
            correlationId = Activity.Current?.TraceId.ToString() ?? Guid.NewGuid().ToString("N");

        exchange.Properties[CorrelationProperty] = correlationId!;

        // Set on In: the pipeline merges Out into In between steps, and the response mapper carries
        // trailer headers across when it builds Out.
        exchange.In.Headers[GrpcHeaders.TrailerPrefix + "x-correlation-id"] = correlationId!;

        return Task.CompletedTask;
    }

    /// <summary>
    /// Names the operation for the steps in Core that key on it — the idempotency cache composes its
    /// record name from scope, operation, caller and the caller's <c>Idempotency-Key</c>. Over HTTP the
    /// name comes from the request path; here it is the method address, which is the same thing one
    /// transport over. Without it every gRPC operation would share the bucket <c>default</c> and two
    /// different calls carrying one key would collide.
    /// <para>
    /// The <c>Idempotency-Key</c> itself needs no step: the caller sends it as metadata and the connector
    /// puts it on the exchange verbatim.
    /// </para>
    /// </summary>
    public static Func<IExchange, CancellationToken, Task> TagOperation(string operation)
    {
        return (exchange, _) =>
        {
            exchange.In.Headers["operation"] = operation;
            return Task.CompletedTask;
        };
    }

    /// <summary>
    /// Turns an OAuth error into a gRPC status. Without this an <c>invalid_client</c> would reach the
    /// caller as a successful call carrying an error document — which no generated client inspects.
    /// <para>
    /// The machine-readable code and description also go into trailers: a non-OK gRPC response has its
    /// payload discarded by clients, so the body is not a place to put them.
    /// </para>
    /// Wire this BEFORE the response mapper, while the answer is still a dictionary.
    /// </summary>
    /// <summary>
    /// Merge strategy for the hop into Core, used with <c>Enrich</c> rather than <c>To</c>.
    /// <para>
    /// <c>To</c> hands Core the facade's own exchange, and several Core processors end their work with
    /// <c>exchange.Stop()</c> - the per-IP limiter and the granular guard among them. That flag lives on the
    /// exchange, so the facade's own pipeline stopped too, and the reply left as a raw dictionary that never
    /// went through status mapping or protobuf encoding. Precisely the security-relevant answers were the
    /// ones that lost their status.
    /// </para>
    /// <para>
    /// <c>Enrich</c> sends a <c>CloneLinked</c> copy instead: same exchange id, same DI scope, same
    /// properties, its own stop flag. Core decides freely and we still get to answer.
    /// </para>
    /// </summary>
    public static IExchange AdoptCoreAnswer(IExchange facade, IExchange core)
    {
        // A genuine fault Core did not handle stays a fault: rethrown here it reaches the consumer exactly
        // as it did through To, and becomes a gRPC status there. Swallowing it would answer OK with the
        // request body still in place.
        if (core.Exception is not null && !core.ExceptionHandled)
            ExceptionDispatchInfo.Capture(core.Exception).Throw();

        var answer = core.HasOut ? core.Out! : core.In;

        facade.In.Body = answer.Body;
        foreach (var header in answer.Headers)
            facade.In.Headers[header.Key] = header.Value;

        // Returning the facade exchange, not the clone: the enricher copies `merged.Exception` onward, and
        // a handled exception - the limiter's marker, for one - is not something to re-raise here.
        return facade;
    }

    public static Task MapErrorToGrpcStatus(IExchange exchange, CancellationToken ct)
    {
        var target = exchange.HasOut ? exchange.Out! : exchange.In;
        var answer = ReadAnswer(exchange);

        // A status Core decided itself comes first. Rate limiting answers 429, the granular guard 403, a
        // database outage 503 - all of them through redbHttp.ResponseCode, because that is the vocabulary
        // every processor in Core speaks. It also carries Retry-After into a trailer, and a non-OK gRPC
        // reply discards its payload, so a trailer is the only place that advice survives.
        MapResponseCode(exchange);

        if (answer is null
            || !answer.TryGetValue("error", out var errorValue) || errorValue is not string error)
        {
            return Task.CompletedTask;
        }

        var description = answer.TryGetValue("error_description", out var d) ? d as string : null;

        // The machine-readable code always travels, whoever decided the status.
        target.Headers[GrpcHeaders.TrailerPrefix + "error"] = error;
        if (!string.IsNullOrEmpty(description))
            target.Headers[GrpcHeaders.TrailerPrefix + "error-description"] = description!;

        // Core's own verdict wins. Deriving the status from the error string instead would demote a
        // rate-limited answer, whose error is `rate_limited` and appears in no RFC 6749 table, to
        // InvalidArgument, and hide the one signal that tells the caller to back off.
        if (!target.Headers.ContainsKey(GrpcHeaders.StatusCode))
        {
            // RFC 6749 5.2 semantics, expressed in the gRPC status space. Same table the HTTP facade uses
            // for status codes, one translation further.
            var status = error switch
            {
                "invalid_client" or "invalid_token" => StatusCode.Unauthenticated,
                "access_denied" or "unauthorized_client" => StatusCode.PermissionDenied,
                "server_error" => StatusCode.Internal,
                "temporarily_unavailable" => StatusCode.Unavailable,
                _ => StatusCode.InvalidArgument,
            };
            target.Headers[GrpcHeaders.StatusCode] = (int)status;
        }

        // The error document says more than "upstream answered 429" ever could.
        target.Headers[GrpcHeaders.StatusDetail] = description ?? error;

        return Task.CompletedTask;
    }

    /// <summary>
    /// Translates a <c>redbHttp.ResponseCode</c> set by Core into a gRPC status. The mapping is the one
    /// the connector applies to the transport-neutral <c>status.code</c>, so both vocabularies land on the
    /// same answer.
    /// </summary>
    private static Task MapResponseCode(IExchange exchange)
    {
        var source = exchange.HasOut ? exchange.Out! : exchange.In;

        if (!source.Headers.TryGetValue("redbHttp.ResponseCode", out var raw) || raw is null)
            return Task.CompletedTask;

        if (!int.TryParse(raw.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var code))
            return Task.CompletedTask;

        var status = code switch
        {
            >= 200 and <= 299 => StatusCode.OK,
            400 or 422 => StatusCode.InvalidArgument,
            401 => StatusCode.Unauthenticated,
            403 => StatusCode.PermissionDenied,
            404 => StatusCode.NotFound,
            405 or 501 => StatusCode.Unimplemented,
            409 => StatusCode.AlreadyExists,
            412 or 428 => StatusCode.FailedPrecondition,
            429 => StatusCode.ResourceExhausted,
            503 => StatusCode.Unavailable,
            504 => StatusCode.DeadlineExceeded,
            >= 500 => StatusCode.Internal,
            _ => StatusCode.Unknown,
        };

        if (status == StatusCode.OK) return Task.CompletedTask;

        source.Headers[GrpcHeaders.StatusCode] = (int)status;

        // Not `??=`: the header dictionary's indexer throws on a missing key, so a compound assignment
        // would fail exactly in the common case where no detail has been set yet.
        if (!source.Headers.ContainsKey(GrpcHeaders.StatusDetail))
            source.Headers[GrpcHeaders.StatusDetail] = $"Upstream answered {code}.";

        // Rate limiting says when to come back; that is actionable and must not be lost with the payload.
        if (source.Headers.TryGetValue("Retry-After", out var retryAfter) && retryAfter is not null)
            source.Headers[GrpcHeaders.TrailerPrefix + "retry-after"] = retryAfter;

        return Task.CompletedTask;
    }

    // ── envelope fallback ────────────────────────────────────

    /// <summary>Exchange property carrying the resolved endpoint for the envelope route.</summary>
    public const string EndpointProperty = "identity:grpc-endpoint";

    /// <summary>
    /// Operations reachable through the generic envelope. Deliberately the same six the typed contract
    /// publishes — the envelope is a second spelling of one surface, not a second surface.
    /// </summary>
    private static readonly Dictionary<string, string> EnvelopeOperations = new(StringComparer.OrdinalIgnoreCase)
    {
        ["token"] = IdentityEndpoints.Token,
        ["introspect"] = IdentityEndpoints.Introspect,
        ["revoke"] = IdentityEndpoints.Revoke,
        ["userinfo"] = IdentityEndpoints.Userinfo,
        ["discovery"] = IdentityEndpoints.Discovery,
        ["jwks"] = IdentityEndpoints.Jwks,
    };

    /// <summary>
    /// Prepares an envelope call: the operation comes from the <c>operation</c> header the caller sets,
    /// the body is JSON. This is the path for callers that do not want to carry
    /// <c>identity.v1.proto</c> — scripts, ad-hoc tooling, languages without protobuf tooling at hand.
    /// </summary>
    public static Task MapEnvelopeRequest(IExchange exchange, CancellationToken ct)
    {
        var operation = exchange.In.GetHeader<string>("operation");

        if (string.IsNullOrWhiteSpace(operation))
            return Reject(exchange, StatusCode.InvalidArgument,
                $"Envelope calls need an 'operation' header. Known: {string.Join(", ", EnvelopeOperations.Keys)}.");

        if (!EnvelopeOperations.TryGetValue(operation!, out var endpoint))
            return Reject(exchange, StatusCode.Unimplemented,
                $"Unknown operation '{operation}'. Known: {string.Join(", ", EnvelopeOperations.Keys)}.");

        exchange.Properties[EndpointProperty] = endpoint;

        try
        {
            exchange.In.Body = ParseJsonParameters(exchange.In.Body);
        }
        catch (JsonException ex)
        {
            return Reject(exchange, StatusCode.InvalidArgument,
                $"Envelope body must be a JSON object of request parameters: {ex.Message}");
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Answers a caller error by setting the status and stopping the route, rather than by throwing.
    /// <para>
    /// This is not a style preference. <c>RouteContext</c> collects builder-level exception handlers from
    /// <b>every</b> builder in the context and wraps each route with them, so Core's catch-all
    /// (<c>OnException&lt;Exception&gt;().Handled()</c>) would swallow a thrown <c>RpcException</c> and
    /// replace the answer with its generic <c>server_error</c> document — the caller would see a stringified
    /// dictionary instead of the status we chose. Setting the status keeps the answer ours.
    /// </para>
    /// </summary>
    private static Task Reject(IExchange exchange, StatusCode status, string detail)
    {
        exchange.Out = new Message(Array.Empty<byte>());
        exchange.Out.Headers[GrpcHeaders.StatusCode] = (int)status;
        exchange.Out.Headers[GrpcHeaders.StatusDetail] = detail;
        exchange.Stop();

        return Task.CompletedTask;
    }

    /// <summary>Encodes the boundary's answer back as JSON — the envelope's wire format.</summary>
    public static Task MapEnvelopeResponse(IExchange exchange, CancellationToken ct)
    {
        var answer = ReadAnswer(exchange) ?? new Dictionary<string, object?>();

        exchange.Out ??= new Message();
        CarryStatusHeaders(exchange.In, exchange.Out!);
        exchange.Out!.Body = JsonSerializer.SerializeToUtf8Bytes(answer, EnvelopeJson);

        return Task.CompletedTask;
    }

    private static readonly JsonSerializerOptions EnvelopeJson = new()
    {
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>
    /// Reads the envelope payload as a flat parameter map. The boundary takes string parameters, so a
    /// nested JSON object would be meaningless here — numbers and booleans are stringified, which is
    /// exactly what the form-encoded wire has always done.
    /// </summary>
    internal static Dictionary<string, string> ParseJsonParameters(object? body)
    {
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal);

        var bytes = body as byte[];
        if (bytes is null || bytes.Length == 0) return parameters;

        JsonElement root;
        // Both failures below surface as JsonException so the caller of this method can turn them into a
        // status; see MapEnvelopeRequest.
        root = JsonSerializer.Deserialize<JsonElement>(bytes);

        if (root.ValueKind != JsonValueKind.Object)
            throw new JsonException("expected an object of request parameters");

        foreach (var property in root.EnumerateObject())
        {
            var value = property.Value.ValueKind switch
            {
                JsonValueKind.String => property.Value.GetString(),
                JsonValueKind.Null or JsonValueKind.Undefined => null,
                _ => property.Value.GetRawText(),
            };

            if (!string.IsNullOrEmpty(value))
                parameters[property.Name] = value!;
        }

        return parameters;
    }

    /// <summary>
    /// Reads the boundary's answer. Identity's convention is that a processor may write into
    /// <c>Out</c> or back into <c>In</c>, so both are checked — the same fallback the SOAP consumer uses.
    /// </summary>
    /// <summary>
    /// The answer as a dictionary, whatever shape it arrived in. Core's own processors hand back a
    /// dictionary; the controller dispatcher and the auth gates hand back serialized JSON. Reading only
    /// the first shape meant a refusal that came as bytes carried no status at all — the caller saw OK.
    /// </summary>
    private static IDictionary<string, object?>? ReadAnswer(IExchange exchange)
    {
        var body = exchange.HasOut ? exchange.Out!.Body : exchange.In.Body;

        if (body is IDictionary<string, object?> dictionary) return dictionary;

        var json = body switch
        {
            byte[] bytes when bytes.Length > 0 => bytes,
            string text when text.Length > 0 => Encoding.UTF8.GetBytes(text),
            _ => null,
        };
        if (json is null) return null;

        try
        {
            using var document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind != JsonValueKind.Object) return null;

            // Only what the status mapping reads. Materialising the whole document here would copy a
            // payload we are about to discard anyway: a non-OK gRPC reply carries no body.
            var answer = new Dictionary<string, object?>();
            foreach (var name in ErrorFields)
            {
                if (document.RootElement.TryGetProperty(name, out var value)
                    && value.ValueKind == JsonValueKind.String)
                {
                    answer[name] = value.GetString();
                }
            }

            return answer.Count > 0 ? answer : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static readonly string[] ErrorFields = ["error", "error_description"];

    private static void Emit(IExchange exchange, IMessage response)
    {
        exchange.Out ??= new Message();

        // The status may have been decided while the answer still sat on In — the pipeline merges Out
        // into In between steps, so MapErrorToGrpcStatus often writes there. The consumer reads the
        // status off the Out message, so without carrying these across a failed call would answer OK.
        CarryStatusHeaders(exchange.In, exchange.Out!);

        exchange.Out!.Body = response.ToByteArray();
    }

    internal static void CarryStatusHeaders(RouteMessage source, RouteMessage target)
    {
        foreach (var (key, value) in source.Headers)
        {
            if (value is null) continue;

            var isStatus = key.Equals(GrpcHeaders.StatusCode, StringComparison.OrdinalIgnoreCase)
                           || key.Equals(GrpcHeaders.StatusDetail, StringComparison.OrdinalIgnoreCase)
                           || key.StartsWith(GrpcHeaders.TrailerPrefix, StringComparison.OrdinalIgnoreCase);

            if (isStatus && !target.Headers.ContainsKey(key))
                target.Headers[key] = value;
        }
    }
}
