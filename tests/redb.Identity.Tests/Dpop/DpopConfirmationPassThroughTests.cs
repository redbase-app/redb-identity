using System.Security.Claims;
using AwesomeAssertions;
using redb.Identity.Core.OpenIddict.Handlers;
using Xunit;

namespace redb.Identity.Tests.Dpop;

/// <summary>
/// Which tokens skip OpenIddict 7's proof-of-possession check (it knows only mTLS and throws on a DPoP
/// <c>jkt</c>): DPoP-only confirmations do, certificate-bound and plain bearer tokens do not.
/// </summary>
public sealed class DpopConfirmationPassThroughTests
{
    [Theory]
    [InlineData("{\"jkt\":\"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I\"}", true)]
    [InlineData("{\"x5t#S256\":\"bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2\"}", false)]
    [InlineData("{\"jkt\":\"a\",\"x5t#S256\":\"b\"}", false)]
    [InlineData("not json", false)]
    public void Recognises_dpop_only_confirmations(string cnf, bool expected)
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("cnf", cnf, "JSON")], "test"));

        DpopConfirmationPassThrough.IsDpopOnly(principal).Should().Be(expected);
    }

    [Fact]
    public void A_bearer_token_without_cnf_is_left_alone()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "u1")], "test"));

        DpopConfirmationPassThrough.IsDpopOnly(principal).Should().BeFalse();
        DpopConfirmationPassThrough.IsDpopOnly(null).Should().BeFalse();
    }
}
