using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using redb.Identity.Contracts.Configuration;
using redb.Identity.Http.Processors;
using redb.Identity.Http.Security;
using redb.Identity.Tests.Infrastructure;
using redb.Route.Abstractions;
using Xunit;

namespace redb.Identity.Tests.Http;

/// <summary>
/// Two cookies in one response leave as two <c>Set-Cookie</c> lines, never folded into one.
/// <para>
/// The federation callback answers with the new session cookie and with the expiry of the per-flow
/// binding cookie. It joined them into one header value with <c>", "</c>. A browser does not split
/// <c>Set-Cookie</c> on commas (RFC 6265 §3: origin servers SHOULD NOT fold): everything after the first
/// <c>;</c> is read as attributes of the <b>first</b> cookie, and of several <c>Max-Age</c> attributes the
/// last one wins (§5.3 step 3). The folded value ends in the binding cookie's <c>Max-Age=0</c> — so the
/// browser deleted the fresh session cookie the moment it arrived, and never cleared the binding cookie
/// either. The HTTP consumer already writes an array value as one header line per entry; the fix is to
/// hand it an array.
/// </para>
/// <para>
/// The session-cookie writers had the neighbouring defect in latent form: each assigned the header, so a
/// second cookie on the same response would silently replace the first. No route pairs two of them
/// today, which is why that part is pinned rather than reported.
/// </para>
/// </summary>
public sealed class SetCookieFoldingTests
{
    private const string BindingCookie = "redb_fed_b";

    private static string SessionCookie() => IdentityCookieFormatter.Build(
        "redb.identity.session", "TICKET", maxAgeSeconds: 28800,
        secure: true, sameSite: CookieSameSiteMode.Lax, useHostPrefix: false);

    /// <summary>The header value as the separate lines the consumer will write.</summary>
    private static string[] Lines(object? value) => value switch
    {
        string s => new[] { s },
        string[] a => a,
        _ => throw new InvalidOperationException($"Set-Cookie of unexpected shape: {value?.GetType().Name ?? "null"}"),
    };

    /// <summary>A line read the way RFC 6265 §5.2-5.3 reads it: name, and the last Max-Age wins.</summary>
    private static (string Name, int? MaxAge) AsBrowserReadsIt(string line)
    {
        var parts = line.Split(';');
        var name = parts[0].Split('=', 2)[0].Trim();
        int? maxAge = null;
        foreach (var attribute in parts.Skip(1))
        {
            var kv = attribute.Split('=', 2);
            if (kv.Length == 2 && kv[0].Trim().Equals("Max-Age", StringComparison.OrdinalIgnoreCase)
                && int.TryParse(kv[1].Trim(), out var seconds))
            {
                maxAge = seconds;
            }
        }
        return (name, maxAge);
    }

    [Theory]
    [InlineData("/account")] // success with a return address: redirect
    [InlineData(null)]       // success without one: the success page
    public async Task Federation_success_keeps_the_session_cookie_alive_and_clears_the_binding_cookie(string? returnUrl)
    {
        IExchange e = new TestExchange();
        e.In.Body = new Dictionary<string, object?> { ["success"] = true, ["returnUrl"] = returnUrl };
        e.In.Headers["Set-Cookie"] = SessionCookie(); // set upstream by the session-cookie writer
        e.Properties["federation-binding-secure"] = true;

        await FederationHttpProcessors.HandleCallbackResponse(e, CancellationToken.None, BindingCookie);

        var lines = Lines(e.Out!.Headers["Set-Cookie"]).Select(AsBrowserReadsIt).ToList();

        lines.Should().ContainSingle(l => l.Name == "redb.identity.session")
            .Which.MaxAge.Should().Be(28800,
                "folded into one line, the binding cookie's Max-Age=0 becomes the session cookie's last Max-Age "
                + "and the browser deletes the session the moment it is set");
        lines.Should().ContainSingle(l => l.Name == BindingCookie,
                "the binding cookie's expiry has to be a cookie of its own, or the browser never sees it")
            .Which.MaxAge.Should().Be(0);
    }

    [Fact]
    public async Task A_session_writer_adds_its_cookie_instead_of_replacing_one_already_there()
    {
        var ticketService = new SessionTicketService(new EphemeralDataProtectionProvider());
        IExchange e = new TestExchange();
        e.In.Body = new Dictionary<string, object?>
        {
            ["success"] = true, ["userId"] = 42L, ["username"] = "alice", ["sessionId"] = 7L,
        };
        e.In.Headers["Set-Cookie"] = IdentityCookieFormatter.Build(
            "other", "x", maxAgeSeconds: 60, secure: true, sameSite: CookieSameSiteMode.Lax, useHostPrefix: false);

        await SessionCookieProcessors.WriteSessionCookie(e, CancellationToken.None, ticketService,
            TimeSpan.FromHours(8), secure: true, bareCookieName: "redb.identity.session",
            sameSite: CookieSameSiteMode.Lax, useHostPrefix: false);

        Lines(e.In.Headers["Set-Cookie"]).Select(l => AsBrowserReadsIt(l).Name)
            .Should().BeEquivalentTo(new[] { "other", "redb.identity.session" });
    }

    [Fact]
    public async Task A_single_cookie_still_leaves_as_a_plain_string()
    {
        // The shape every other consumer of the header already reads; only a second cookie changes it.
        var ticketService = new SessionTicketService(new EphemeralDataProtectionProvider());
        IExchange e = new TestExchange();
        e.In.Body = new Dictionary<string, object?>
        {
            ["success"] = true, ["userId"] = 42L, ["username"] = "alice",
        };

        await SessionCookieProcessors.WriteSessionCookie(e, CancellationToken.None, ticketService,
            TimeSpan.FromHours(8), secure: true, bareCookieName: "redb.identity.session",
            sameSite: CookieSameSiteMode.Lax, useHostPrefix: false);

        e.In.Headers["Set-Cookie"].Should().BeOfType<string>();
    }
}
