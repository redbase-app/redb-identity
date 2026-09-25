using System.Xml.Linq;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Soap;

/// <summary>
/// F4–F5 end to end: WS-Trust against the real Core. A token is issued, validated, cancelled, and seen
/// dead afterwards — the same issuer, the same client registry and the same token store the other
/// transports use. That is the acceptance criterion the whole facade exists for: a client registered over
/// HTTP gets a token over SOAP.
/// </summary>
[Collection("PostgresCollection")]
public class SoapProtocolFlowTests : IClassFixture<SoapIdentityFixture>
{
    private readonly SoapIdentityFixture _fixture;

    public SoapProtocolFlowTests(SoapIdentityFixture fixture) => _fixture = fixture;

    private static readonly XNamespace Wst = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
    private static readonly XNamespace Soap = "http://schemas.xmlsoap.org/soap/envelope/";

    private const string Trust = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
    private const string IssueAction = Trust + "/RST/Issue";
    private const string ValidateAction = Trust + "/RST/Validate";
    private const string CancelAction = Trust + "/RST/Cancel";

    private static string IssueRequest(string scope) => $"""
        <wst:RequestSecurityToken xmlns:wst="{Trust}"
                                  xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"
                                  xmlns:wsa="http://www.w3.org/2005/08/addressing">
          <wst:RequestType>{Trust}/Issue</wst:RequestType>
          <wsp:AppliesTo>
            <wsa:EndpointReference><wsa:Address>{scope}</wsa:Address></wsa:EndpointReference>
          </wsp:AppliesTo>
        </wst:RequestSecurityToken>
        """;

    private static string TargetRequest(string verb, string token) => $"""
        <wst:RequestSecurityToken xmlns:wst="{Trust}"
                                  xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
          <wst:RequestType>{Trust}/{verb}</wst:RequestType>
          <wst:{verb}Target>
            <wsse:BinarySecurityToken>{token}</wsse:BinarySecurityToken>
          </wst:{verb}Target>
        </wst:RequestSecurityToken>
        """;

    private static XElement Body(string envelope) =>
        XElement.Parse(envelope).Element(Soap + "Body")
        ?? throw new InvalidOperationException("The response carried no SOAP body:\n" + envelope);

    private static string? FaultCode(string envelope)
    {
        var fault = Body(envelope).Descendants().FirstOrDefault(e => e.Name.LocalName == "Fault");
        return fault?.Descendants().FirstOrDefault(e => e.Name.LocalName is "faultcode" or "Value")?.Value;
    }

    private static string ReadToken(string envelope)
    {
        var token = Body(envelope).Descendants()
            .FirstOrDefault(e => e.Name.LocalName == "BinarySecurityToken")
            ?? throw new InvalidOperationException("No token in the response:\n" + envelope);

        return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(token.Value.Trim()));
    }

    private async Task<string> IssueToken() =>
        ReadToken(await _fixture.PostAsync(IssueAction, IssueRequest(SoapIdentityFixture.GrantedScope)));

    [Fact]
    public async Task A_client_registered_over_http_gets_a_token_over_soap()
    {
        var envelope = await _fixture.PostAsync(IssueAction, IssueRequest(SoapIdentityFixture.GrantedScope));

        var body = Body(envelope);
        body.Descendants().Should().Contain(e => e.Name == Wst + "RequestSecurityTokenResponseCollection");

        // A JWT, which is what the RSTR carries by the F0 decision — same issuer, same signature, same
        // lifetime as on every other transport, because it is literally the same object.
        var token = ReadToken(envelope);
        token.Split('.').Should().HaveCount(3);

        body.Descendants().Should().Contain(e => e.Name.LocalName == "Lifetime");
    }

    [Fact]
    public async Task An_issued_token_validates_then_dies_on_cancel()
    {
        var token = await IssueToken();

        var valid = await _fixture.PostAsync(ValidateAction, TargetRequest("Validate", token));
        Body(valid).Descendants().First(e => e.Name.LocalName == "Code").Value
            .Should().EndWith("status/valid");

        var cancelled = await _fixture.PostAsync(CancelAction, TargetRequest("Cancel", token));
        Body(cancelled).Descendants().Should()
            .Contain(e => e.Name.LocalName == "RequestedTokenCancelled");

        // Revocation took effect, and how that is reported matters as much as that it is.
        //
        // OpenIddict reports a revoked token as an error rather than as RFC 7662's `active: false` — the
        // repo records the same behaviour in IntrospectionRevocationTests — and the facade used to pass
        // that straight through as a wst:FailedAuthentication fault. That answer is about the caller,
        // and the caller was fine: they authenticated, asked whether a token was alive, and deserve the
        // truthful «no» that WS-Trust has a status code for. A fault would send them to debug their own
        // credentials, and a revoked token is the ordinary reason to run Validate at all.
        //
        // So the assertion is on the shape of the answer, not merely on «not valid»: the weaker form was
        // satisfied by the fault too, which is why it stayed green while the behaviour was wrong.
        var after = await _fixture.PostAsync(ValidateAction, TargetRequest("Validate", token));

        Body(after).Descendants().Should()
            .NotContain(e => e.Name.LocalName == "Fault", "a dead token is an answer, not a refusal");

        Body(after).Descendants().First(e => e.Name.LocalName == "Code").Value
            .Should().EndWith("status/invalid");
    }

    /// <summary>
    /// The wrong secret has to be refused, and refused as a fault: a client that receives a successful
    /// response carrying an error document has no reason to open it.
    /// </summary>
    [Fact]
    public async Task A_wrong_secret_is_refused_as_a_fault()
    {
        var envelope = await _fixture.PostAsync(
            IssueAction, IssueRequest(SoapIdentityFixture.GrantedScope),
            password: "not-the-secret");

        FaultCode(envelope).Should().Be("wst:FailedAuthentication");
    }

    /// <summary>
    /// No credentials at all is a different failure from wrong credentials, and both must be refusals.
    /// The dangerous outcome would be a token issued to an anonymous caller.
    /// </summary>
    [Fact]
    public async Task An_anonymous_request_is_refused()
    {
        var envelope = await _fixture.PostAsync(
            IssueAction, IssueRequest(SoapIdentityFixture.GrantedScope), username: null);

        FaultCode(envelope).Should().NotBeNullOrEmpty();
        envelope.Should().NotContain("BinarySecurityToken");
    }

    /// <summary>
    /// A scope the client was never granted must not be issued. The client registry is the same one HTTP
    /// uses, so this proves the facade did not become a second place where permissions are decided.
    /// </summary>
    [Fact]
    public async Task A_scope_the_client_may_not_have_is_refused()
    {
        var envelope = await _fixture.PostAsync(IssueAction, IssueRequest("identity:nonexistent-scope"));

        envelope.Should().NotContain("BinarySecurityToken");
        FaultCode(envelope).Should().NotBeNullOrEmpty();
    }

    /// <summary>
    /// The contract is served on GET. The audience for this facade builds clients with generators, and a
    /// generator needs a document to read — an STS that answers only POST is one a WCF or CXF developer
    /// cannot start from.
    /// </summary>
    [Fact]
    public async Task The_wsdl_is_published_and_points_at_this_endpoint()
    {
        using var response = await _fixture.GetWsdlAsync();

        response.IsSuccessStatusCode.Should().BeTrue();

        var wsdl = await response.Content.ReadAsStringAsync();
        wsdl.Should().Contain("RequestSecurityToken");

        // The shipped document names a placeholder address; a copy fetched from a live endpoint has to
        // point back at that endpoint, or a generated client calls the wrong host.
        wsdl.Should().Contain($"127.0.0.1:{_fixture.Port}");
    }

    /// <summary>
    /// A correct refusal reaches the caller as a fault and is not counted as a failure of the route.
    /// <para>
    /// Before, the STS threw its WS-Trust faults. The caller got the right fault either way, but each one
    /// also failed the exchange: a supervisor saw <c>soap-identity-sts</c> reporting errors for requests it
    /// had refused exactly as designed — the demo suite's negative probes alone produced three — and a
    /// real breakage would have drowned in them. Read from the route's own
    /// <c>redb.route.exchanges.failed</c> counter, filtered to this fixture's endpoint by its port, since
    /// the meter is process-wide and other SOAP fixtures run the same route id.
    /// </para>
    /// </summary>
    [Fact]
    public async Task A_refusal_is_a_fault_on_the_wire_and_not_a_failure_of_the_route()
    {
        long failed = 0, seen = 0;
        using var listener = new System.Diagnostics.Metrics.MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name == redb.Route.Telemetry.RouteMetrics.MeterName
                && instrument.Name is "redb.route.exchanges.failed" or "redb.route.exchange.duration")
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((_, value, tags, _) =>
        {
            if (IsThisFixture(tags)) Interlocked.Add(ref failed, value);
        });
        // Duration is recorded for every exchange whatever its outcome ("processed" counts only the
        // successful ones), so it is the honest proof that the listener sees this route at all.
        listener.SetMeasurementEventCallback<double>((_, _, tags, _) =>
        {
            if (IsThisFixture(tags)) Interlocked.Increment(ref seen);
        });
        listener.Start();

        var malformed = await _fixture.PostAsync(IssueAction, "<not-an-rst/>");
        var badSecret = await _fixture.PostAsync(IssueAction, IssueRequest(SoapIdentityFixture.GrantedScope),
            password: "not-the-secret");

        FaultCode(malformed).Should().Be("wst:InvalidRequest");
        FaultCode(badSecret).Should().Be("wst:FailedAuthentication");

        Interlocked.Read(ref seen).Should().BeGreaterThanOrEqualTo(2,
            "the listener must see this route's exchanges, or a zero below would prove nothing");
        Interlocked.Read(ref failed).Should().Be(0,
            "both requests were refused exactly as designed; a refusal is the STS's answer, not a failure");
    }

    private bool IsThisFixture(ReadOnlySpan<KeyValuePair<string, object?>> tags)
    {
        foreach (var tag in tags)
        {
            if (tag.Key != "redb.route.endpoint" || tag.Value is not string endpoint) continue;
            var match = System.Text.RegularExpressions.Regex.Match(endpoint, @"[?&]port=(\d+)");
            return match.Success && match.Groups[1].Value == _fixture.Port.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        return false;
    }
}
