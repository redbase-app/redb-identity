using System.Xml.Linq;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Soap;

/// <summary>
/// F6 — the per-IP limiter, over SOAP, for real.
/// <para>
/// This is the test that would notice if the connection bridge silently stopped working. The limiter
/// reads an address the SOAP consumer has to publish itself; when that publishing is missing the
/// limiter sees nothing and does nothing, which looks in a log exactly like a well-behaved caller.
/// </para>
/// </summary>
[Collection("PostgresCollection")]
public class SoapRateLimitTests : IClassFixture<SoapThrottledIdentityFixture>
{
    private readonly SoapThrottledIdentityFixture _fixture;

    public SoapRateLimitTests(SoapThrottledIdentityFixture fixture) => _fixture = fixture;

    private const string Trust = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
    private static readonly XNamespace Soap = "http://schemas.xmlsoap.org/soap/envelope/";

    private static string IssueRequest() => $"""
        <wst:RequestSecurityToken xmlns:wst="{Trust}">
          <wst:RequestType>{Trust}/Issue</wst:RequestType>
        </wst:RequestSecurityToken>
        """;

    [Fact]
    public async Task A_caller_over_the_per_ip_limit_is_refused()
    {
        string? rejection = null;

        // A couple more than the limit: enough to cross it, few enough that a failure names a number
        // rather than «somewhere in a hundred calls».
        for (var attempt = 1; attempt <= SoapThrottledIdentityFixture.PerIpPerMinute + 2; attempt++)
        {
            var envelope = await _fixture.PostAsync(Trust + "/RST/Issue", IssueRequest());

            var fault = XElement.Parse(envelope).Element(Soap + "Body")?
                .Descendants().FirstOrDefault(e => e.Name.LocalName == "Fault");

            if (fault is null) continue;

            var reason = fault.Descendants()
                .FirstOrDefault(e => e.Name.LocalName is "faultstring" or "Text")?.Value;

            // Only a refusal about rate counts. A wrong-credentials fault would end the loop just as
            // early and prove nothing about the limiter.
            if (reason is not null && reason.Contains("many", StringComparison.OrdinalIgnoreCase))
            {
                rejection = reason;
                break;
            }
        }

        rejection.Should().NotBeNull(
            "the per-IP limit is {0}/minute, so a run of {1} calls from one address must be cut short",
            SoapThrottledIdentityFixture.PerIpPerMinute,
            SoapThrottledIdentityFixture.PerIpPerMinute + 2);
    }
}
