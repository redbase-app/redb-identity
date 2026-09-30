using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Http;

/// <summary>
/// A <c>Set-Cookie</c> the caller puts on its request never comes back in the response.
/// <para>
/// The HTTP consumer copies every request header into the exchange, and Identity's routes answer on the
/// same message. The consumer refuses to echo a request header, but since it learned to tell a value the
/// client sent from one the route wrote (it compares the very object it placed there), it only refuses the
/// untouched value. Identity's cookie writers <i>add</i> to whatever <c>Set-Cookie</c> is already on the
/// message — which, on a login answered on the request message, was the caller's own. The new array held
/// the caller's cookie and ours, it was no longer the object the client sent, and both lines went out.
/// A browser cannot send <c>Set-Cookie</c> on a request (a forbidden header name), so this only ever
/// reached the caller itself; it is still a value the server must not repeat. The name is stripped on
/// ingress with the other names a caller must never supply.
/// </para>
/// </summary>
[Collection("ProductionHttp")]
public sealed class InboundSetCookieTests
{
    private readonly ProductionHttpFixture _fx;

    public InboundSetCookieTests(ProductionHttpFixture fx) => _fx = fx;

    [Fact]
    public async Task A_set_cookie_sent_by_the_caller_is_never_returned_to_it()
    {
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false })
        {
            BaseAddress = new Uri(_fx.BaseUrl),
        };
        using var request = new HttpRequestMessage(System.Net.Http.HttpMethod.Post, "/login")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["username"] = ProductionHttpFixture.TestUsername,
                ["password"] = ProductionHttpFixture.TestPassword,
            }),
        };
        request.Headers.TryAddWithoutValidation("Set-Cookie", "injected=from-the-caller; Path=/")
            .Should().BeTrue("the test needs the header on the request to prove it does not come back");

        using var response = await http.SendAsync(request);

        var lines = response.Headers.TryGetValues("Set-Cookie", out var values) ? values.ToList() : new List<string>();

        lines.Should().Contain(l => l.Contains("redb.identity.session"),
            "the login must still issue its session cookie — otherwise this test would prove nothing");
        lines.Should().NotContain(l => l.Contains("injected"),
            "a value the caller sent is not the server's to repeat, least of all as a cookie");
    }
}
