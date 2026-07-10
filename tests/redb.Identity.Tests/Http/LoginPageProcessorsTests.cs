using System.Net;
using FluentAssertions;
using redb.Identity.Http.Processors;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.Http;
using Xunit;

namespace redb.Identity.Tests.Http;

public class LoginPageProcessorsTests
{
    [Fact]
    public async Task RenderLoginPage_RendersHtml()
    {
        var exchange = CreateExchange();

        await LoginPageProcessors.RenderLoginPage(exchange, CancellationToken.None);

        exchange.Out.Should().NotBeNull();
        var body = exchange.Out!.Body as string;
        body.Should().NotBeNull();
        body.Should().Contain("Sign In");
        body.Should().Contain("<form");
        body.Should().Contain("action=\"/login\"");
        exchange.Out.GetHeader<string>(HttpHeaders.ResponseContentType).Should().Contain("text/html");
        exchange.Out.GetHeader<int>(HttpHeaders.ResponseCode).Should().Be(200);
    }

    [Fact]
    public async Task RenderLoginPage_PreservesReturnUrl()
    {
        var exchange = CreateExchange();
        exchange.In.Headers[HttpHeaders.Query] = "returnUrl=%2Fconnect%2Fauthorize%3Fclient_id%3Dapp";

        await LoginPageProcessors.RenderLoginPage(exchange, CancellationToken.None);

        var body = exchange.Out!.Body as string;
        body.Should().Contain("/connect/authorize?client_id=app");
    }

    [Fact]
    public async Task RenderLoginPage_HtmlEncodesReturnUrl()
    {
        var exchange = CreateExchange();
        exchange.In.Headers[HttpHeaders.Query] = "returnUrl=%3Cscript%3Ealert(1)%3C%2Fscript%3E";

        await LoginPageProcessors.RenderLoginPage(exchange, CancellationToken.None);

        var body = exchange.Out!.Body as string;
        body.Should().NotContain("<script>alert(1)</script>");
        body.Should().Contain("&lt;script&gt;");
    }

    [Fact]
    public async Task HandleLoginResponse_SuccessWithReturnUrl_Redirects()
    {
        var exchange = CreateExchange();
        exchange.Out = new Message();
        exchange.Out.Body = new Dictionary<string, object?>
        {
            ["success"] = true,
            ["returnUrl"] = "/connect/authorize?client_id=app"
        };

        await LoginPageProcessors.HandleLoginResponse(exchange, CancellationToken.None);

        exchange.Out.GetHeader<int>(HttpHeaders.ResponseCode).Should().Be(302);
        exchange.Out.GetHeader<string>("Location").Should().Be("/connect/authorize?client_id=app");
    }

    [Fact]
    public async Task HandleLoginResponse_SuccessNoReturnUrl_ReturnsJson()
    {
        var exchange = CreateExchange();
        exchange.Out = new Message();
        exchange.Out.Body = new Dictionary<string, object?>
        {
            ["success"] = true
        };

        await LoginPageProcessors.HandleLoginResponse(exchange, CancellationToken.None);

        var body = exchange.Out.Body as Dictionary<string, object?>;
        body.Should().NotBeNull();
        body!["message"].Should().Be("Login successful");
    }

    [Fact]
    public async Task HandleLoginResponse_OpenRedirect_Blocked()
    {
        var exchange = CreateExchange();
        exchange.Out = new Message();
        exchange.Out.Body = new Dictionary<string, object?>
        {
            ["success"] = true,
            ["returnUrl"] = "//evil.com/phish"
        };

        await LoginPageProcessors.HandleLoginResponse(exchange, CancellationToken.None);

        // Should NOT redirect — treated as open redirect
        var body = exchange.Out.Body as Dictionary<string, object?>;
        body.Should().NotBeNull();
        body!["message"].Should().Be("Login successful");
    }

    [Fact]
    public async Task HandleLoginResponse_AbsoluteUrl_Blocked()
    {
        var exchange = CreateExchange();
        exchange.Out = new Message();
        exchange.Out.Body = new Dictionary<string, object?>
        {
            ["success"] = true,
            ["returnUrl"] = "https://evil.com"
        };

        await LoginPageProcessors.HandleLoginResponse(exchange, CancellationToken.None);

        // Should NOT redirect — absolute URL
        var body = exchange.Out.Body as Dictionary<string, object?>;
        body.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleLoginResponse_BackslashRedirect_Blocked()
    {
        var exchange = CreateExchange();
        exchange.Out = new Message();
        exchange.Out.Body = new Dictionary<string, object?>
        {
            ["success"] = true,
            ["returnUrl"] = "/\\evil.com"
        };

        await LoginPageProcessors.HandleLoginResponse(exchange, CancellationToken.None);

        // Should NOT redirect — /\ is open redirect vector
        var body = exchange.Out.Body as Dictionary<string, object?>;
        body.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleLoginResponse_Failure_RendersFormWithError()
    {
        var exchange = CreateExchange();
        exchange.Out = new Message();
        exchange.Out.Body = new Dictionary<string, object?>
        {
            ["success"] = false,
            ["error_description"] = "Invalid username or password"
        };

        await LoginPageProcessors.HandleLoginResponse(exchange, CancellationToken.None);

        var body = exchange.Out.Body as string;
        body.Should().NotBeNull();
        body.Should().Contain("Invalid username or password");
        body.Should().Contain("Sign In");
    }

    private static IExchange CreateExchange() => new Exchange(new Message());
}
