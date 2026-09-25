using System.Diagnostics;
using System.Xml;
using System.Xml.Linq;
using redb.Identity.Contracts;
using redb.Identity.Contracts.Routes;
using redb.Route.Abstractions;
using redb.Route.Soap;

namespace redb.Identity.Soap.Processors;

/// <summary>
/// The steps that bridge WS-Trust to what Core expects. Same shape as the gRPC facade's processors, and
/// for the same reason: the facade names the operation, translates, calls Core, translates back. It
/// decides nothing about the protocol itself.
/// </summary>
internal static class SoapIdentityProcessors
{
    /// <summary>Exchange property holding the resolved WS-Trust request type for later steps.</summary>
    public const string RequestTypeProperty = "identity:wstrust-request-type";

    /// <summary>Exchange property holding the core address this request is bound for.</summary>
    public const string EndpointProperty = "identity:wstrust-endpoint";

    /// <summary>Exchange property holding the scope asked for, echoed back into the answer.</summary>
    public const string ScopeProperty = "identity:wstrust-scope";

    // ── request ──────────────────────────────────────────────

    /// <summary>
    /// Parses the RST, names the operation, and turns it into the parameters Core takes. Every failure
    /// here is the caller's, so it leaves as a fault with a WS-Trust code rather than as a server error —
    /// and as the STS's answer, not as a failure of the route (<see cref="AnswerRefusals"/>).
    /// </summary>
    public static Task MapRequest(IExchange exchange, CancellationToken ct) =>
        AnswerRefusals(exchange, () => ParseRequest(exchange));

    private static void ParseRequest(IExchange exchange)
    {
        var bodyXml = exchange.In.Body as string ?? exchange.In.Body?.ToString();
        if (string.IsNullOrWhiteSpace(bodyXml))
            throw Fault.InvalidRequest("The request carried no SOAP body.");

        XElement body;
        try
        {
            body = XElement.Parse(bodyXml, LoadOptions.None);
        }
        catch (XmlException ex)
        {
            throw Fault.InvalidRequest($"The request body is not well-formed XML: {ex.Message}");
        }

        var rst = WsTrust.FindRst(body)
                  ?? throw Fault.InvalidRequest("No wst:RequestSecurityToken element in the body.");

        var action = exchange.In.GetHeader<string>(SoapHeaders.Action);
        var requestType = WsTrust.ResolveRequestType(action, rst)
                          ?? throw Fault.InvalidRequest(
                              "Unknown request type. Expected Issue, Validate, Cancel or Renew, named by " +
                              "the WS-Addressing Action or by wst:RequestType.");

        var parameters = BuildParameters(exchange, rst, requestType);

        exchange.Properties[RequestTypeProperty] = requestType;
        exchange.Properties[EndpointProperty] = EndpointFor(requestType);
        if (WsTrust.ReadScope(rst) is { } scope) exchange.Properties[ScopeProperty] = scope;

        exchange.In.Body = parameters;
    }

    /// <summary>
    /// Runs a step, and turns a WS-Trust refusal it raises into the STS's answer.
    /// <para>
    /// A malformed RST, bad credentials, a scope the caller may not have, a caller over the rate limit:
    /// each is the service doing exactly what it is built to do, and the caller must receive a
    /// <c>soap:Fault</c> with the right code. Thrown, the same fault reached the wire just as well — and
    /// also failed the exchange, so every correct refusal counted as a route error, filled a dead-letter
    /// channel and showed the STS as a failing route to whoever supervises it. Instead the refusal is put
    /// on the reply (<see cref="SoapHeaders.FaultCode"/>, <see cref="SoapHeaders.FaultString"/>) and the
    /// route stops; the SOAP consumer sends the fault and the exchange stays successful.
    /// </para>
    /// <para>
    /// Only <see cref="WsTrustRefusal"/> is caught. A <c>soap:Server</c> fault — Core gave no answer, is
    /// unavailable, timed out — is our side breaking, and it keeps propagating as a failure, because that
    /// is precisely what the error count and the dead-letter channel exist to catch.
    /// </para>
    /// </summary>
    private static Task AnswerRefusals(IExchange exchange, Action step)
    {
        try
        {
            step();
        }
        catch (WsTrustRefusal refusal)
        {
            // The same message the consumer reads the reply from.
            var reply = exchange.HasOut ? exchange.Out! : exchange.In;
            reply.Headers[SoapHeaders.FaultCode] = refusal.FaultCode;
            reply.Headers[SoapHeaders.FaultString] = refusal.FaultString;
            exchange.Stop();
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// The whole of the WS-Trust to OAuth translation. Client credentials come from the WS-Security
    /// UsernameToken, which the transport has already read; the token a request operates on comes from
    /// the request's own target element.
    /// </summary>
    private static Dictionary<string, string> BuildParameters(
        IExchange exchange, XElement rst, string requestType)
    {
        var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // UsernameToken is how a WS-Trust caller presents itself, and it maps onto the client credentials
        // every other transport sends as fields. Core reads exactly these names, so no separate
        // authentication path appears here.
        if (exchange.In.GetHeader<string>(SoapHeaders.Username) is { Length: > 0 } username)
            parameters["client_id"] = username;
        if (exchange.In.GetHeader<string>(SoapHeaders.Password) is { Length: > 0 } password)
            parameters["client_secret"] = password;

        switch (requestType)
        {
            case WsTrust.Issue:
                parameters["grant_type"] = "client_credentials";
                if (WsTrust.ReadScope(rst) is { } scope) parameters["scope"] = scope;
                break;

            case WsTrust.Renew:
                parameters["grant_type"] = "refresh_token";
                parameters["refresh_token"] = RequireTarget(rst, requestType);
                break;

            case WsTrust.Validate:
            case WsTrust.Cancel:
                parameters["token"] = RequireTarget(rst, requestType);
                break;
        }

        return parameters;
    }

    private static string RequireTarget(XElement rst, string requestType) =>
        WsTrust.ReadTargetToken(rst, requestType)
        ?? throw Fault.InvalidRequest($"{requestType} needs a token in its wst:{requestType}Target element.");

    private static string EndpointFor(string requestType) => requestType switch
    {
        WsTrust.Issue => IdentityEndpoints.Token,
        WsTrust.Renew => IdentityEndpoints.Token,
        WsTrust.Validate => IdentityEndpoints.Introspect,
        WsTrust.Cancel => IdentityEndpoints.Revoke,
        _ => throw Fault.InvalidRequest($"Unsupported request type '{requestType}'."),
    };

    // ── the hop into Core ────────────────────────────────────

    /// <summary>
    /// Merge strategy for the hop into Core, used with <c>Enrich</c> rather than <c>To</c>.
    /// <para>
    /// <c>To</c> would hand Core the facade's own exchange, and several Core processors end their work
    /// with <c>exchange.Stop()</c> — the per-IP limiter and the granular guard among them. That flag
    /// lives on the exchange, so the facade's own pipeline would stop too and the reply would leave as a
    /// raw dictionary, never having been turned into a SOAP response. Precisely the security-relevant
    /// answers were the ones that would lose their shape.
    /// </para>
    /// </summary>
    public static IExchange AdoptCoreAnswer(IExchange facade, IExchange core)
    {
        // A genuine fault Core did not handle stays a fault: rethrown here it reaches the consumer and
        // becomes a SOAP fault there. Swallowing it would answer success with the request still in place.
        if (core.Exception is not null && !core.ExceptionHandled)
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(core.Exception).Throw();

        var answer = core.HasOut ? core.Out! : core.In;

        facade.In.Body = answer.Body;
        foreach (var header in answer.Headers)
            facade.In.Headers[header.Key] = header.Value;

        return facade;
    }

    // ── response ─────────────────────────────────────────────

    /// <summary>
    /// Turns Core's answer into the RSTR the caller expects, or into a fault. Which of the two is
    /// decided by the answer itself, not by the transport. A refusal leaves as the STS's answer, a
    /// breakage on our side as a failure (<see cref="AnswerRefusals"/>).
    /// </summary>
    public static Task MapResponse(IExchange exchange, CancellationToken ct) =>
        AnswerRefusals(exchange, () => RenderAnswer(exchange));

    private static void RenderAnswer(IExchange exchange)
    {
        var answer = ReadAnswer(exchange);
        var requestType = exchange.Properties.TryGetValue(RequestTypeProperty, out var rt)
            ? rt as string ?? WsTrust.Issue
            : WsTrust.Issue;

        if (answer is null)
            throw Fault.Server("The identity core returned no answer.");

        // A refusal must leave as a fault: a WS-Trust client reads the fault, not the body of a
        // response it was told succeeded.
        //
        // The status Core stated is what decides, not the error string. Reading the string alone would
        // demote a rate-limited answer — whose error is `rate_limited` and appears in no RFC 6749 table —
        // to «malformed request», telling a caller to fix what is not broken instead of to wait. The gRPC
        // facade learned this the same way; the reading now lives once, in IdentityVerdict.
        var error = Read(answer, "error");
        var verdict = IdentityVerdict.Resolve(ReadResponseCode(exchange), error);

        if (verdict.IsRefusal())
        {
            var reason = Read(answer, "error_description")
                         ?? error
                         ?? $"The identity core refused the request ({verdict}).";

            // Validate asks a question about a token, so an answer about that token is not a refusal of
            // the request: the caller authenticated fine and got a truthful «no». Answering
            // FailedAuthentication here would tell them their own credentials are bad and send them to
            // debug the wrong thing — and this is the ordinary case, since a revoked or expired token is
            // exactly what a caller runs Validate to discover.
            //
            // A refusal that is about the caller rather than the token still leaves as a fault.
            if (requestType == WsTrust.Validate && IsAboutTheToken(error))
            {
                Emit(exchange, WsTrust.BuildStatusResponse(valid: false, reason));
                return;
            }

            throw Fault.FromVerdict(verdict, reason);
        }

        // Validate is the exception to the rule above: an inactive token is a legitimate answer, not an
        // error, and WS-Trust says it with a status code (RFC 7662 §2.2 for the introspection side).
        if (requestType == WsTrust.Validate)
        {
            var active = answer.TryGetValue("active", out var a) && a is true or "true" or "True";
            Emit(exchange, WsTrust.BuildStatusResponse(active, active ? null : "The token is not active."));
            return;
        }

        if (requestType == WsTrust.Cancel)
        {
            Emit(exchange, WsTrust.BuildCancelResponse());
            return;
        }

        var accessToken = Read(answer, "access_token")
                          ?? throw Fault.Server("The identity core issued no access token.");

        long? expiresIn = null;
        if (answer.TryGetValue("expires_in", out var raw) && raw is not null
            && long.TryParse(raw.ToString(), out var seconds))
        {
            expiresIn = seconds;
        }

        var scope = Read(answer, "scope")
                    ?? (exchange.Properties.TryGetValue(ScopeProperty, out var s) ? s as string : null);

        Emit(exchange, WsTrust.BuildIssueResponse(accessToken, expiresIn, scope));
    }

    /// <summary>
    /// Names the operation for the steps in Core that key on it. Core composes its idempotency record
    /// from scope, operation, caller and the caller's key; without a name every call through this facade
    /// would share the bucket "default".
    /// </summary>
    public static Func<IExchange, CancellationToken, Task> TagOperation(string operation) =>
        (exchange, _) =>
        {
            exchange.In.Headers["operation"] = operation;
            return Task.CompletedTask;
        };

    /// <summary>
    /// Carries the caller's correlation id, or invents one from the ambient trace. WS-Trust has no field
    /// for this, so it travels as a SOAP header the caller may send and always comes back in the answer.
    /// </summary>
    public static Task PropagateCorrelationId(IExchange exchange, CancellationToken ct)
    {
        // First step on the SOAP route: the WS-Trust listener is HTTP, so the caller's request headers
        // land in In.Headers verbatim and Core trusts the reserved names (audit attribution,
        // credentials, idempotency operation). Same list as the HTTP and gRPC facades.
        redb.Identity.Contracts.Routes.IdentityReservedInboundHeaders.Strip(exchange.In.Headers);

        var supplied = exchange.In.GetHeader<string>("X-Correlation-Id")
                       ?? exchange.In.GetHeader<string>(SoapHeaders.HeaderPrefix + "CorrelationId");

        var correlationId = string.IsNullOrWhiteSpace(supplied)
            ? Activity.Current?.TraceId.ToString() ?? Guid.NewGuid().ToString("N")
            : supplied!;

        exchange.Properties["identity:correlation-id"] = correlationId;
        exchange.In.Headers["X-Correlation-Id"] = correlationId;
        return Task.CompletedTask;
    }

    // ── helpers ──────────────────────────────────────────────

    /// <summary>
    /// Whether a refusal concerns the token that was asked about rather than the caller who asked.
    /// <para>
    /// Only these two are the token's own: everything else Core can refuse with — a bad client secret,
    /// a rate limit, our own failure — is about the caller or about us, and stays a fault so they are
    /// not told «that token is dead» when the truth is «we would not answer you».
    /// </para>
    /// </summary>
    private static bool IsAboutTheToken(string? error) =>
        error is "invalid_token" or "invalid_grant";

    private static IDictionary<string, object?>? ReadAnswer(IExchange exchange)
    {
        var body = exchange.HasOut ? exchange.Out!.Body : exchange.In.Body;
        return body as IDictionary<string, object?>;
    }

    private static string? Read(IDictionary<string, object?> answer, string key) =>
        answer.TryGetValue(key, out var value) && value is not null ? value.ToString() : null;

    /// <summary>
    /// Core's own verdict, as a status code. It travels as a header rather than in the body, so it
    /// survives an answer whose body is an error document and one whose body is a token alike.
    /// </summary>
    private static int? ReadResponseCode(IExchange exchange)
    {
        var source = exchange.HasOut ? exchange.Out! : exchange.In;
        return source.Headers.TryGetValue(IdentityVerdict.ResponseCodeHeader, out var raw)
            ? IdentityVerdict.ParseResponseCode(raw)
            : null;
    }

    /// <summary>
    /// Writes the response body. The transport wraps it in an envelope, so what leaves here is the body
    /// payload and nothing more.
    /// </summary>
    private static void Emit(IExchange exchange, XElement payload)
    {
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = payload.ToString(SaveOptions.DisableFormatting);
        exchange.Out.ContentType = "text/xml";
    }
}
