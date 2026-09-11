using System.Xml.Linq;
using FluentAssertions;
using redb.Identity.Contracts.Routes;
using redb.Identity.Soap;
using redb.Identity.Soap.Processors;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.Soap;
using Xunit;

namespace redb.Identity.Tests.Soap;

/// <summary>
/// F2 and F4–F5 — the translation itself: a WS-Trust request becomes the parameters the core takes, and
/// the core's answer becomes an RSTR or a fault. Nothing here talks to a socket; the point is the mapping.
/// </summary>
public class SoapIdentityProcessorsTests
{
    private static readonly XNamespace Wst = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
    private static readonly XNamespace Wsp = "http://schemas.xmlsoap.org/ws/2004/09/policy";
    private static readonly XNamespace Wsa = "http://www.w3.org/2005/08/addressing";

    private const string IssueAction = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue";
    private const string ValidateAction = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Validate";
    private const string CancelAction = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Cancel";
    private const string RenewAction = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Renew";

    private static IExchange Request(string bodyXml, string? action = null,
        string? username = null, string? password = null)
    {
        var message = new Message(bodyXml);
        if (action is not null) message.Headers[SoapHeaders.Action] = action;
        if (username is not null) message.Headers[SoapHeaders.Username] = username;
        if (password is not null) message.Headers[SoapHeaders.Password] = password;
        return new Exchange(message);
    }

    private static string Rst(params object[] content) =>
        new XElement(Wst + "RequestSecurityToken", content).ToString();

    private static Dictionary<string, string> Parameters(IExchange exchange) =>
        (Dictionary<string, string>)exchange.In.Body!;

    // ── request ──────────────────────────────────────────────

    [Fact]
    public async Task Reserved_internal_headers_on_the_soap_request_are_stripped_on_ingress()
    {
        // The WS-Trust listener is HTTP: the caller's request headers land in In.Headers verbatim and
        // Core trusts the reserved names (audit attribution on Issue / Validate / Cancel, credentials,
        // idempotency operation). The UsernameToken is the only sanctioned credential path.
        var exchange = Request(Rst(), action: IssueAction, username: "svc", password: "pw");
        foreach (var name in redb.Identity.Contracts.Routes.IdentityReservedInboundHeaders.Names)
            exchange.In.Headers[name] = "forged";
        exchange.In.Headers["X-Correlation-Id"] = "caller-trace-9";

        await SoapIdentityProcessors.PropagateCorrelationId(exchange, default);

        foreach (var name in redb.Identity.Contracts.Routes.IdentityReservedInboundHeaders.Names)
            exchange.In.Headers.ContainsKey(name).Should().BeFalse($"'{name}' must only ever be set by a facade processor");
        exchange.In.Headers[SoapHeaders.Username].Should().Be("svc", "the WS-Security UsernameToken is legitimate caller input");
        exchange.Properties["identity:correlation-id"].Should().Be("caller-trace-9");
    }

    /// <summary>
    /// The UsernameToken is how a WS-Trust caller presents itself, and it has to become the very fields
    /// the core already reads. A separate authentication path in the facade would be a second place that
    /// decides who a caller is.
    /// </summary>
    [Fact]
    public async Task Issue_becomes_a_client_credentials_grant_with_the_username_token()
    {
        var exchange = Request(
            Rst(new XElement(Wsp + "AppliesTo",
                new XElement(Wsa + "EndpointReference",
                    new XElement(Wsa + "Address", "identity:read")))),
            IssueAction, username: "svc-billing", password: "s3cret");

        await SoapIdentityProcessors.MapRequest(exchange, default);

        var parameters = Parameters(exchange);
        parameters["grant_type"].Should().Be("client_credentials");
        parameters["client_id"].Should().Be("svc-billing");
        parameters["client_secret"].Should().Be("s3cret");

        // AppliesTo is how WS-Trust says «what is this token for»; scope is how the core says it.
        parameters["scope"].Should().Be("identity:read");

        exchange.Properties[SoapIdentityProcessors.EndpointProperty].Should().Be(IdentityEndpoints.Token);
    }

    /// <summary>
    /// The Action is the specification's own way of naming the operation, and it is what generators emit.
    /// The body's <c>RequestType</c> is the fallback, because clients that omit the addressing header are
    /// common enough that refusing them would be refusing the audience this facade exists for.
    /// </summary>
    [Fact]
    public async Task The_request_type_is_read_from_the_body_when_the_action_is_absent()
    {
        var exchange = Request(Rst(
            new XElement(Wst + "RequestType",
                "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Cancel"),
            new XElement(Wst + "CancelTarget", "token-abc")));

        await SoapIdentityProcessors.MapRequest(exchange, default);

        Parameters(exchange)["token"].Should().Be("token-abc");
        exchange.Properties[SoapIdentityProcessors.EndpointProperty].Should().Be(IdentityEndpoints.Revoke);
    }

    [Fact]
    public async Task Validate_carries_the_target_token_to_introspection()
    {
        var exchange = Request(
            Rst(new XElement(Wst + "ValidateTarget", "token-xyz")), ValidateAction);

        await SoapIdentityProcessors.MapRequest(exchange, default);

        Parameters(exchange)["token"].Should().Be("token-xyz");
        exchange.Properties[SoapIdentityProcessors.EndpointProperty]
            .Should().Be(IdentityEndpoints.Introspect);
    }

    [Fact]
    public async Task Renew_becomes_a_refresh_token_grant()
    {
        var exchange = Request(
            Rst(new XElement(Wst + "RenewTarget", "refresh-abc")), RenewAction);

        await SoapIdentityProcessors.MapRequest(exchange, default);

        var parameters = Parameters(exchange);
        parameters["grant_type"].Should().Be("refresh_token");
        parameters["refresh_token"].Should().Be("refresh-abc");
        exchange.Properties[SoapIdentityProcessors.EndpointProperty].Should().Be(IdentityEndpoints.Token);
    }

    /// <summary>
    /// A malformed request is the caller's error and must say so in their vocabulary. Left as a plain
    /// exception it would reach them as <c>soap:Server</c> — «we broke» — and they would wait for us to
    /// fix something that is theirs to fix.
    /// </summary>
    [Theory]
    [InlineData("<not-an-rst/>", "RequestSecurityToken")]
    [InlineData("<wst:RequestSecurityToken xmlns:wst=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\"/>",
        "Unknown request type")]
    public async Task A_malformed_request_faults_with_a_ws_trust_code(string body, string expected)
    {
        var call = async () => await SoapIdentityProcessors.MapRequest(Request(body), default);

        var fault = (await call.Should().ThrowAsync<SoapFaultException>()).Which;
        fault.FaultCode.Should().Be("wst:InvalidRequest");
        fault.FaultString.Should().Contain(expected);
    }

    [Fact]
    public async Task Cancel_without_a_target_faults_rather_than_revoking_nothing()
    {
        var call = async () => await SoapIdentityProcessors.MapRequest(Request(Rst(), CancelAction), default);

        (await call.Should().ThrowAsync<SoapFaultException>())
            .Which.FaultCode.Should().Be("wst:InvalidRequest");
    }

    // ── response ─────────────────────────────────────────────

    private static IExchange Answer(string requestType, Dictionary<string, object?> body, int? responseCode = null)
    {
        var message = new Message(body);
        if (responseCode is { } code)
            message.Headers["redbHttp.ResponseCode"] = code;

        var exchange = new Exchange(message);
        exchange.Properties[SoapIdentityProcessors.RequestTypeProperty] = requestType;
        return exchange;
    }

    [Fact]
    public async Task An_issued_token_comes_back_as_a_binary_security_token()
    {
        var exchange = Answer("Issue", new Dictionary<string, object?>
        {
            ["access_token"] = "header.payload.signature",
            ["expires_in"] = 3600,
            ["scope"] = "identity:read",
        });

        await SoapIdentityProcessors.MapResponse(exchange, default);

        var rstr = XElement.Parse((string)exchange.Out!.Body!);
        rstr.Name.Should().Be(Wst + "RequestSecurityTokenResponseCollection");

        var token = rstr.Descendants().First(e => e.Name.LocalName == "BinarySecurityToken");
        var decoded = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(token.Value));
        decoded.Should().Be("header.payload.signature");

        // A client that caches tokens has to know when to stop using them.
        rstr.Descendants().Should().Contain(e => e.Name.LocalName == "Lifetime");
    }

    /// <summary>
    /// An inactive token is a legitimate answer to «is this good», not an error — RFC 7662 §2.2 says so
    /// for introspection, and WS-Trust says it with a status code rather than a fault.
    /// </summary>
    [Theory]
    [InlineData(true, "status/valid")]
    [InlineData(false, "status/invalid")]
    public async Task Validate_answers_with_a_status_not_with_the_introspection_document(
        bool active, string expectedCode)
    {
        var exchange = Answer("Validate", new Dictionary<string, object?>
        {
            ["active"] = active,
            ["sub"] = "user-1",
        });

        await SoapIdentityProcessors.MapResponse(exchange, default);

        var rstr = XElement.Parse((string)exchange.Out!.Body!);
        rstr.Descendants().First(e => e.Name.LocalName == "Code").Value.Should().Contain(expectedCode);

        // The introspection document is deliberately not echoed: the caller asked a yes-or-no question.
        rstr.ToString().Should().NotContain("user-1");
    }

    [Fact]
    public async Task Cancel_answers_that_the_token_was_cancelled()
    {
        var exchange = Answer("Cancel", new Dictionary<string, object?>());

        await SoapIdentityProcessors.MapResponse(exchange, default);

        XElement.Parse((string)exchange.Out!.Body!)
            .Descendants().Should().Contain(e => e.Name.LocalName == "RequestedTokenCancelled");
    }

    /// <summary>
    /// A refusal has to leave as a fault. A client that gets a successful response carrying an error
    /// document has no reason to open it, and generated WS-Trust clients branch on the fault code.
    /// </summary>
    [Theory]
    [InlineData("invalid_client", "wst:FailedAuthentication")]
    [InlineData("access_denied", "wst:FailedAuthentication")]
    [InlineData("invalid_scope", "wst:InvalidScope")]
    [InlineData("invalid_request", "wst:InvalidRequest")]
    [InlineData("server_error", "soap:Server")]
    public async Task An_error_document_becomes_the_fault_ws_trust_has_for_it(string error, string expectedCode)
    {
        var exchange = Answer("Issue", new Dictionary<string, object?>
        {
            ["error"] = error,
            ["error_description"] = "the reason",
        });

        var call = async () => await SoapIdentityProcessors.MapResponse(exchange, default);

        var fault = (await call.Should().ThrowAsync<SoapFaultException>()).Which;
        fault.FaultCode.Should().Be(expectedCode);

        // The code names the kind of refusal; the reason carries what the code cannot.
        fault.FaultString.Should().Be("the reason");
    }

    /// <summary>
    /// The status the core stated wins over the error string. This is the lesson the gRPC facade paid
    /// for: read from the string alone, <c>rate_limited</c> appears in no RFC 6749 table, falls through
    /// to «malformed request», and tells a caller to fix a request that is not broken instead of to wait.
    /// </summary>
    [Fact]
    public async Task The_cores_own_status_decides_not_the_error_string()
    {
        var exchange = Answer("Issue", new Dictionary<string, object?>
        {
            ["error"] = "rate_limited",
            ["error_description"] = "Too many requests.",
        }, responseCode: 429);

        var call = async () => await SoapIdentityProcessors.MapResponse(exchange, default);

        var fault = (await call.Should().ThrowAsync<SoapFaultException>()).Which;

        // WS-Trust has no code for rate limiting, and of the two available readings the refusal is ours,
        // not the caller's — so it must not read as a defect in their request.
        fault.FaultCode.Should().Be("soap:Server");
        fault.FaultCode.Should().NotBe("wst:InvalidRequest");
    }

    /// <summary>
    /// A refusal Core states only as a status code, with no error document at all, is still a refusal.
    /// Answering it as success would hand the caller an RSTR with no token in it.
    /// </summary>
    [Fact]
    public async Task A_status_code_alone_is_enough_to_refuse()
    {
        var exchange = Answer("Issue", new Dictionary<string, object?>(), responseCode: 403);

        var call = async () => await SoapIdentityProcessors.MapResponse(exchange, default);

        (await call.Should().ThrowAsync<SoapFaultException>())
            .Which.FaultCode.Should().Be("wst:FailedAuthentication");
    }
}
