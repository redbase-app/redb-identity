using FluentAssertions;
using redb.Identity.Http.Processors;
using Xunit;

namespace redb.Identity.Tests.Security;

/// <summary>
/// A <c>returnUrl</c> may only lead back into this server.
/// <para>
/// The value comes from the query string of the login page and travels through login, MFA, federation
/// and consent before it becomes a <c>Location</c> header. Every one of those five redirect points asks
/// <see cref="LoginPageProcessors.IsValidReturnUrl"/> first, and the check refused absolute URLs and the
/// protocol-relative <c>//host</c> and <c>/\host</c>. It did not refuse control characters — and a browser
/// removes ASCII tab and newline from a URL before resolving it (WHATWG URL: "remove all ASCII tab or
/// newline from input"). So <c>returnUrl=%2F%09%2Fevil.example</c>, decoded to <c>/\t/evil.example</c>,
/// passed the check and landed the user on <c>//evil.example</c>: another host, straight after they typed
/// their password on ours. ASP.NET Core's <c>IsLocalUrl</c> rejects control characters for this reason.
/// </para>
/// </summary>
public sealed class ReturnUrlOpenRedirectTests
{
    [Theory]
    [InlineData("/")]
    [InlineData("/account")]
    [InlineData("/connect/authorize?client_id=app&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&state=s")]
    public void A_local_path_is_accepted(string url) =>
        LoginPageProcessors.IsValidReturnUrl(url).Should().BeTrue();

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("https://evil.example/")]
    [InlineData("evil.example")]
    [InlineData("//evil.example")]
    [InlineData("/\\evil.example")]
    public void An_absolute_or_protocol_relative_url_is_refused(string? url) =>
        LoginPageProcessors.IsValidReturnUrl(url).Should().BeFalse();

    [Theory]
    [InlineData("/\t/evil.example")]
    [InlineData("/\n/evil.example")]
    [InlineData("/\r/evil.example")]
    [InlineData("/\t\\evil.example")]
    [InlineData("/\0/evil.example")]
    [InlineData("/account\t")]
    public void A_control_character_is_refused_because_the_browser_would_drop_it(string url) =>
        LoginPageProcessors.IsValidReturnUrl(url).Should().BeFalse(
            "a browser strips tab and newline before resolving, which turns \"/\\t/host\" into \"//host\" — "
            + "an open redirect right after the user signed in");
}
