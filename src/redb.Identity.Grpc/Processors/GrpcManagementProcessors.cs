using System.Globalization;
using System.Text;
using System.Text.Json;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Grpc.Core;
using redb.Identity.Grpc.Management.V1;
using redb.Identity.Management;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.Grpc;

namespace redb.Identity.Grpc.Processors;

/// <summary>
/// F6 — the management surface over gRPC: authenticate, authorize, then dispatch to the very same
/// controller the HTTP facade dispatches to.
/// <para>
/// Sharing the controllers is the point. They are thin — each action validates its DTO and forwards to a
/// <c>direct-vm://identity-manage-*</c> route — but "thin" is not "trivial": which argument is a key,
/// which key name a surface uses, when validation runs. Restating that per transport is a second
/// declaration of the contract, and the copy that drifts is the one that accepts what the other rejects.
/// So the controllers moved to <c>redb.Identity.Management</c> and both facades dispatch the same types.
/// </para>
/// <para>
/// Every gate here fails closed. The authentication and authorization hops run on isolated exchanges (see
/// <see cref="GrpcIdentityProcessors.AdoptCoreAnswer"/> for why), so their <c>exchange.Stop()</c> no
/// longer ends this route by itself — the gate is explicit, and it halts unless it positively sees an
/// allow.
/// </para>
/// </summary>
internal static class GrpcManagementProcessors
{
    /// <summary>Property set when a gate refused, read by <see cref="RequireAuthorized"/>.</summary>
    private const string RefusedProperty = "identity:grpc-refused";

    /// <summary>
    /// Names the call before either gate runs: which controller action serves it, and — for the
    /// authorization gate — which resource and action it amounts to.
    /// </summary>
    public static Func<IExchange, CancellationToken, Task> Describe(ManagementOperation operation)
    {
        return (exchange, _) =>
        {
            // The controller dispatcher routes on this header rather than on a path.
            exchange.In.Headers["dispatch-method"] = operation.DispatchMethod;

            // The same canonical resource identifiers the HTTP facade passes, so the single table in Core
            // decides for both transports and neither can drift into granting more than the other.
            exchange.Properties["identity:authz-resource"] = operation.Resource;
            exchange.Properties["identity:authz-action"] = operation.Writes ? "write" : "read";

            return Task.CompletedTask;
        };
    }

    /// <summary>
    /// Merge strategy for the two gates. Beyond adopting the answer it carries back the
    /// <c>identity:management-*</c> properties authentication establishes — the isolated exchange is a
    /// copy, so anything Core writes on it is otherwise lost, and losing those properties would silently
    /// disarm the self-vs-admin check the controllers rely on downstream.
    /// </summary>
    public static IExchange AdoptGateDecision(IExchange facade, IExchange core)
    {
        GrpcIdentityProcessors.AdoptCoreAnswer(facade, core);

        foreach (var property in core.Properties)
        {
            if (property.Key.StartsWith("identity:", StringComparison.Ordinal))
                facade.Properties[property.Key] = property.Value;
        }

        // A gate writes an Out only to refuse. Recording it here keeps the decision explicit rather than
        // re-derived later from a body that has since been merged and moved.
        if (core.HasOut) facade.Properties[RefusedProperty] = true;

        return facade;
    }

    /// <summary>
    /// The gate. Halts unless the step before it let the request through, translating the refusal into a
    /// gRPC status first: a refusal delivered as a successful reply carrying an error document would be
    /// worse than no gate at all, because no generated client inspects it.
    /// </summary>
    public static Task RequireAuthorized(IExchange exchange, CancellationToken ct) =>
        Decide(exchange, ct, requireAuthentication: false);

    /// <summary>
    /// The gate after the authentication hop. Unlike <see cref="RequireAuthorized"/> it demands positive
    /// evidence that authentication actually ran — the <c>identity:management-principal</c> the auth
    /// processor leaves behind — instead of merely finding no refusal.
    /// <para>
    /// The difference is not academic. A deployment can wire Core without a management auth processor,
    /// which leaves <c>direct-vm://identity-auth-management</c> unregistered; the hop then throws
    /// «No consumer registered», Core's context-level exception handler marks that handled and replaces
    /// the body with its own error document, and the old gate saw exactly what a successful
    /// authentication looks like: no refusal. The call only stopped because that handler happened to end
    /// the pipeline and because the wire encoder happened to refuse the leftover dictionary — two
    /// unrelated safety nets, neither of them an authentication decision. Absence of a «no» is not a
    /// «yes».
    /// </para>
    /// </summary>
    public static Task RequireAuthenticated(IExchange exchange, CancellationToken ct) =>
        Decide(exchange, ct, requireAuthentication: true);

    private static async Task Decide(IExchange exchange, CancellationToken ct, bool requireAuthentication)
    {
        var refused = exchange.Properties.TryGetValue(RefusedProperty, out var flag) && flag is true;
        var deniedByCode = ReadResponseCode(exchange) is { } code && code is < 200 or > 299;

        // Anonymous routes are a deliberate decision by the auth processor, and it says so explicitly.
        var anonymous = exchange.Properties.TryGetValue("identity:management-anonymous", out var anon)
                        && anon is true;

        var unauthenticated = requireAuthentication
                              && !anonymous
                              && !exchange.Properties.ContainsKey("identity:management-principal");

        if (unauthenticated && !refused && !deniedByCode)
        {
            var stated = exchange.HasOut ? exchange.Out! : exchange.In;
            stated.Headers[GrpcHeaders.StatusCode] = (int)StatusCode.Unauthenticated;
            stated.Headers[GrpcHeaders.StatusDetail] =
                "Authentication did not run for this call. The management surface is closed until it does.";
            stated.Headers[GrpcHeaders.TrailerPrefix + "error"] = "unauthenticated";
            exchange.Properties.Remove(RefusedProperty);
            exchange.Stop();
            return;
        }

        if (!refused && !deniedByCode) return;

        await GrpcIdentityProcessors.MapErrorToGrpcStatus(exchange, ct);

        // Nothing decided a status? Then the refusal came in a shape this code does not recognise, and the
        // only safe reading of an unrecognised answer from an authorization gate is "no".
        var target = exchange.HasOut ? exchange.Out! : exchange.In;
        if (!target.Headers.ContainsKey(GrpcHeaders.StatusCode))
        {
            target.Headers[GrpcHeaders.StatusCode] = (int)StatusCode.PermissionDenied;
            target.Headers[GrpcHeaders.StatusDetail] = "The request was refused.";
        }

        exchange.Properties.Remove(RefusedProperty);
        exchange.Stop();
    }

    /// <summary>
    /// Unwraps <see cref="ManagementRequest"/> into the JSON object the controller dispatcher binds from.
    /// Named arguments, not positional: the wire contract must not be the order of C# parameters.
    /// </summary>
    public static Task MapRequest(IExchange exchange, CancellationToken ct)
    {
        try
        {
            var bytes = exchange.In.Body as byte[] ?? [];
            var request = bytes.Length == 0 ? new ManagementRequest() : ManagementRequest.Parser.ParseFrom(bytes);
            var arguments = request.Arguments ?? new Struct();

            // Protobuf's own JSON mapping renders a Struct as a plain JSON object, which is exactly what
            // the dispatcher expects — no hand-rolled conversion in between to disagree with it.
            exchange.In.Body = Encoding.UTF8.GetBytes(JsonFormatter.Default.Format(arguments));
            return Task.CompletedTask;
        }
        catch (InvalidProtocolBufferException ex)
        {
            return Reject(exchange, StatusCode.InvalidArgument,
                $"Request must be an identity.management.v1.ManagementRequest: {ex.Message}");
        }
    }

    /// <summary>
    /// Turns the controller's answer into a status, using the same table the HTTP facade uses. The
    /// controllers report failure as an error document with a success status, so without this a refusal
    /// would arrive as an OK call — and the acceptance test for this phase is that one token yields the
    /// same verdict on both transports.
    /// </summary>
    public static Task MapControllerErrorToGrpcStatus(IExchange exchange, CancellationToken ct)
    {
        var source = exchange.HasOut ? exchange.Out! : exchange.In;
        if (source.Body is not byte[] json || json.Length == 0) return Task.CompletedTask;

        string? error;
        try
        {
            using var document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind != JsonValueKind.Object) return Task.CompletedTask;
            if (!document.RootElement.TryGetProperty("error", out var value)
                || value.ValueKind != JsonValueKind.String)
            {
                return Task.CompletedTask;
            }

            error = value.GetString();
        }
        catch (JsonException)
        {
            return Task.CompletedTask;   // not JSON: nothing to read a verdict out of
        }

        if (string.IsNullOrEmpty(error)) return Task.CompletedTask;

        // A status the dispatcher (or Core) already decided wins — a missing method is NOT_FOUND and an
        // action that threw is INTERNAL, not INVALID_ARGUMENT. The table, in the package that owns the
        // controllers, speaks only for error documents that came back as a success. Either way the code
        // is translated into the gRPC status space by the same path Core's own verdicts go through.
        source.Headers["redbHttp.ResponseCode"] =
            ManagementErrorCodes.DecidedErrorStatus(source) ?? ManagementErrorCodes.ToStatusCode(error!);
        return GrpcIdentityProcessors.MapErrorToGrpcStatus(exchange, ct);
    }

    /// <summary>
    /// Wraps the controller's JSON answer as <see cref="ManagementResponse"/>. A deletion answers with
    /// nothing, which stays nothing rather than becoming an empty object.
    /// </summary>
    public static Task MapResponse(IExchange exchange, CancellationToken ct)
    {
        var body = exchange.HasOut ? exchange.Out!.Body : exchange.In.Body;

        var response = new ManagementResponse();
        var json = body switch
        {
            byte[] bytes when bytes.Length > 0 => Encoding.UTF8.GetString(bytes),
            string text when text.Length > 0 => text,
            _ => null,
        };

        if (json is not null)
            response.Result = JsonParser.Default.Parse<Value>(json);

        exchange.Out ??= new Message();
        GrpcIdentityProcessors.CarryStatusHeaders(exchange.In, exchange.Out!);
        exchange.Out!.Body = response.ToByteArray();

        return Task.CompletedTask;
    }

    private static Task Reject(IExchange exchange, StatusCode status, string detail)
    {
        exchange.Out = new Message(Array.Empty<byte>());
        exchange.Out.Headers[GrpcHeaders.StatusCode] = (int)status;
        exchange.Out.Headers[GrpcHeaders.StatusDetail] = detail;
        exchange.Stop();

        return Task.CompletedTask;
    }

    private static int? ReadResponseCode(IExchange exchange)
    {
        var source = exchange.HasOut ? exchange.Out! : exchange.In;
        if (!source.Headers.TryGetValue("redbHttp.ResponseCode", out var raw) || raw is null) return null;
        return int.TryParse(raw.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var code)
            ? code
            : null;
    }
}

/// <summary>
/// One management operation as the facade sees it: a wire address, the controller action that serves it,
/// and what the authorization gate should be told it amounts to.
/// </summary>
/// <param name="Service">gRPC service name, e.g. <c>Users</c>.</param>
/// <param name="Method">gRPC method name, e.g. <c>List</c>.</param>
/// <param name="DispatchMethod">Controller action, qualified: <c>Users.List</c>.</param>
/// <param name="Resource">Canonical resource identifier, e.g. <c>/api/v1/identity/users</c>.</param>
/// <param name="Writes">Whether the operation mutates. Read and write map to different scopes.</param>
internal sealed record ManagementOperation(
    string Service,
    string Method,
    string DispatchMethod,
    string Resource,
    bool Writes);
