using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using redb.Identity.Core.Configuration;
using redb.Identity.Http.Security;
using redb.Identity.Http.Processors;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.Http;
using Xunit;
using redb.Identity.Contracts.Configuration;

namespace redb.Identity.Tests.Http;

public class SessionCookieProcessorsTests
{
    private readonly SessionTicketService _ticketService;
    private readonly TimeSpan _maxAge = TimeSpan.FromHours(8);

    public SessionCookieProcessorsTests()
    {
        var provider = new EphemeralDataProtectionProvider();
        _ticketService = new SessionTicketService(provider);
    }

    // ── ReadSessionCookie ──

    [Fact]
    public async Task ReadSessionCookie_ValidCookie_SetsHeaders()
    {
        var ticket = _ticketService.Protect(42, 100, "admin");
        var exchange = CreateExchange();
        exchange.In.Headers["Cookie"] = $"redb.identity.session={ticket}";

        await SessionCookieProcessors.ReadSessionCookie(exchange, CancellationToken.None, _ticketService, _maxAge, SessionCookieProcessors.DefaultCookieName);

        exchange.In.GetHeader<long>("session_user_id").Should().Be(42);
        exchange.In.GetHeader<string>("session_username").Should().Be("admin");
        exchange.In.GetHeader<long>("session_id").Should().Be(100);
    }

    [Fact]
    public async Task ReadSessionCookie_NoCookie_NoHeaders()
    {
        var exchange = CreateExchange();

        await SessionCookieProcessors.ReadSessionCookie(exchange, CancellationToken.None, _ticketService, _maxAge, SessionCookieProcessors.DefaultCookieName);

        exchange.In.Headers.ContainsKey("session_user_id").Should().BeFalse();
    }

    [Fact]
    public async Task ReadSessionCookie_InvalidTicket_NoHeaders()
    {
        var exchange = CreateExchange();
        exchange.In.Headers["Cookie"] = "redb.identity.session=garbage-value";

        await SessionCookieProcessors.ReadSessionCookie(exchange, CancellationToken.None, _ticketService, _maxAge, SessionCookieProcessors.DefaultCookieName);

        exchange.In.Headers.ContainsKey("session_user_id").Should().BeFalse();
    }

    [Fact]
    public async Task ReadSessionCookie_MultipleCookies_FindsCorrectOne()
    {
        var ticket = _ticketService.Protect(7, 50, "user");
        var exchange = CreateExchange();
        exchange.In.Headers["Cookie"] = $"other=value; redb.identity.session={ticket}; another=x";

        await SessionCookieProcessors.ReadSessionCookie(exchange, CancellationToken.None, _ticketService, _maxAge, SessionCookieProcessors.DefaultCookieName);

        exchange.In.GetHeader<long>("session_user_id").Should().Be(7);
    }

    // ── WriteSessionCookie ──

    [Fact]
    public async Task WriteSessionCookie_SuccessfulLogin_SetsCookie()
    {
        var exchange = CreateExchange();
        exchange.Out = new Message();
        exchange.Out.Body = new Dictionary<string, object?>
        {
            ["success"] = true,
            ["userId"] = 42L,
            ["username"] = "admin"
        };

        await SessionCookieProcessors.WriteSessionCookie(exchange, CancellationToken.None, _ticketService, _maxAge, secure: true, SessionCookieProcessors.DefaultCookieName, CookieSameSiteMode.Lax, useHostPrefix: false);

        var setCookie = exchange.Out.GetHeader<string>("Set-Cookie");
        setCookie.Should().NotBeNull();
        setCookie.Should().StartWith("redb.identity.session=");
        setCookie.Should().Contain("HttpOnly");
        setCookie.Should().Contain("Secure");
        setCookie.Should().Contain("SameSite=Lax");
    }

    [Fact]
    public async Task WriteSessionCookie_FailedLogin_NoCookie()
    {
        var exchange = CreateExchange();
        exchange.Out = new Message();
        exchange.Out.Body = new Dictionary<string, object?>
        {
            ["success"] = false,
            ["error"] = "access_denied"
        };

        await SessionCookieProcessors.WriteSessionCookie(exchange, CancellationToken.None, _ticketService, _maxAge, secure: true, SessionCookieProcessors.DefaultCookieName, CookieSameSiteMode.Lax, useHostPrefix: false);

        exchange.Out.Headers.ContainsKey("Set-Cookie").Should().BeFalse();
    }

    // ── ClearSessionCookie ──

    [Fact]
    public async Task ClearSessionCookie_SetsMaxAgeZero()
    {
        var exchange = CreateExchange();
        exchange.Out = new Message();

        await SessionCookieProcessors.ClearSessionCookie(exchange, CancellationToken.None, secure: true, SessionCookieProcessors.DefaultCookieName, CookieSameSiteMode.Lax, useHostPrefix: false);

        var setCookie = exchange.Out.GetHeader<string>("Set-Cookie");
        setCookie.Should().Contain("Max-Age=0");
        setCookie.Should().Contain("redb.identity.session=");
    }

    // ── RedirectToLogin ──

    [Fact]
    public async Task RedirectToLogin_LoginRequired_Redirects()
    {
        var exchange = CreateExchange();
        exchange.In.Headers[HttpHeaders.Query] = "client_id=app&response_type=code";
        exchange.In.Headers[HttpHeaders.Path] = "/connect/authorize";
        exchange.Out = new Message();
        exchange.Out.Body = new Dictionary<string, object?>
        {
            ["error"] = "login_required"
        };

        await SessionCookieProcessors.RedirectToLogin(exchange, CancellationToken.None, "/login");

        exchange.Out.GetHeader<int>(HttpHeaders.ResponseCode).Should().Be(302);
        var location = exchange.Out.GetHeader<string>("Location");
        location.Should().StartWith("/login?returnUrl=");
        location.Should().Contain("connect%2Fauthorize");
    }

    [Fact]
    public async Task RedirectToLogin_NotLoginRequired_NoChange()
    {
        var exchange = CreateExchange();
        exchange.Out = new Message();
        exchange.Out.Body = new Dictionary<string, object?>
        {
            ["code"] = "abc123"
        };

        await SessionCookieProcessors.RedirectToLogin(exchange, CancellationToken.None, "/login");

        exchange.Out.Headers.ContainsKey(HttpHeaders.ResponseCode).Should().BeFalse();
    }

    [Fact]
    public async Task WriteSessionCookie_WithSessionId_EncodesInTicket()
    {
        var exchange = CreateExchange();
        exchange.Out = new Message();
        exchange.Out.Body = new Dictionary<string, object?>
        {
            ["success"] = true,
            ["userId"] = 42L,
            ["username"] = "admin",
            ["sessionId"] = 100L
        };

        await SessionCookieProcessors.WriteSessionCookie(exchange, CancellationToken.None, _ticketService, _maxAge, secure: true, SessionCookieProcessors.DefaultCookieName, CookieSameSiteMode.Lax, useHostPrefix: false);

        var setCookie = exchange.Out.GetHeader<string>("Set-Cookie");
        setCookie.Should().NotBeNull();

        // Extract ticket value and verify it roundtrips with sessionId
        var ticketValue = setCookie!.Split('=', 2)[1].Split(';')[0];
        var ticket = _ticketService.Unprotect(ticketValue, _maxAge);
        ticket.Should().NotBeNull();
        ticket!.SessionId.Should().Be(100);
    }

    // ── RedirectToConsent (N-2 native BFF consent) ──

    [Fact]
    public async Task RedirectToConsent_NoDelegateHeader_Returns302()
    {
        var exchange = BuildConsentRequiredExchange(delegateHeader: null);

        await SessionCookieProcessors.RedirectToConsent(exchange, CancellationToken.None, "/consent");

        exchange.In.GetHeader<int>("redbHttp.ResponseCode").Should().Be(302);
        var location = exchange.In.GetHeader<string>("Location");
        location.Should().NotBeNull();
        location!.Should().StartWith("/consent?client_id=demo-client");
    }

    [Fact]
    public async Task RedirectToConsent_DelegateHeader_ReturnsJson400()
    {
        var exchange = BuildConsentRequiredExchange(delegateHeader: "1");

        await SessionCookieProcessors.RedirectToConsent(exchange, CancellationToken.None, "/consent");

        exchange.In.GetHeader<int>("redbHttp.ResponseCode").Should().Be(400);
        exchange.In.GetHeader<string>("Content-Type").Should().Contain("application/json");

        var body = exchange.In.Body as IDictionary<string, object?>;
        body.Should().NotBeNull();
        body!["error"].Should().Be("consent_required");
        body["clientId"].Should().Be("demo-client");
        body["appName"].Should().Be("Demo App");
        body["scopes"].Should().BeOfType<string[]>()
            .Which.Should().Equal("openid", "profile");
        body["userId"].Should().Be("42");
        body["returnUrl"].Should().Be("/connect/authorize?client_id=demo-client");
    }

    [Fact]
    public async Task RedirectToConsent_DelegateHeader_TrueLiteral_ReturnsJson400()
    {
        var exchange = BuildConsentRequiredExchange(delegateHeader: "True");

        await SessionCookieProcessors.RedirectToConsent(exchange, CancellationToken.None, "/consent");

        exchange.In.GetHeader<int>("redbHttp.ResponseCode").Should().Be(400);
    }

    private static Exchange BuildConsentRequiredExchange(string? delegateHeader)
    {
        var ex = new Exchange(new Message
        {
            Body = new Dictionary<string, object?> { ["error"] = "consent_required" },
        });
        ex.In.Headers["redbHttp.Path"] = "/connect/authorize";
        ex.In.Headers["redbHttp.Query"] = "client_id=demo-client";
        if (delegateHeader is not null)
            ex.In.Headers["X-Identity-Delegate-Consent"] = delegateHeader;
        ex.Properties["consent_client_id"] = "demo-client";
        ex.Properties["consent_app_name"] = "Demo App";
        ex.Properties["consent_scopes"] = "openid profile";
        ex.Properties["consent_user_id"] = "42";
        return ex;
    }

    private static IExchange CreateExchange() => new Exchange(new Message());
}