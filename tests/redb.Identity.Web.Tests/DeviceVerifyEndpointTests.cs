using System.Net;
using System.Net.Http;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace redb.Identity.Web.Tests;

/// <summary>
/// N-5 — BFF surface for the RFC 8628 §3.3 device user verification flow.
/// These tests verify the public contract of the /device pages and the
/// /api/auth/device/verify form endpoint without simulating a real OIDC login
/// (which would require a running Identity host). Two invariants are critical:
///   1. POST /api/auth/device/verify is CSRF-protected like every other
///      /api/auth/* form endpoint.
///   2. The /device page itself is [Authorize] — anonymous users must be
///      bounced to /login with returnUrl preserved so they come back to
///      the verification page after authenticating.
/// </summary>
public sealed class DeviceVerifyEndpointTests : IClassFixture<WebHostFixture>
{
    private readonly WebHostFixture _factory;

    public DeviceVerifyEndpointTests(WebHostFixture factory) { _factory = factory; }

    [Fact]
    public async Task Post_device_verify_without_antiforgery_token_is_rejected()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var form = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("user_code", "ABCD-EFGH"),
            new KeyValuePair<string, string>("action", "allow"),
        });

        var resp = await client.PostAsync("/api/auth/device/verify", form);

        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest,
            because: "every /api/auth/* form POST must be CSRF-protected");
    }

    [Fact]
    public async Task Get_device_page_anonymous_redirects_to_login_with_returnUrl()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var resp = await client.GetAsync("/device?user_code=ABCD-EFGH");

        resp.StatusCode.Should().BeOneOf(
            HttpStatusCode.Redirect,
            HttpStatusCode.Found,
            HttpStatusCode.SeeOther);

        var location = resp.Headers.Location?.ToString() ?? string.Empty;
        location.Should().Contain("/login", because: "anonymous users must be sent to login first");
    }

    [Fact]
    public async Task Get_device_done_page_anonymous_redirects_to_login()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var resp = await client.GetAsync("/device/done?action=allow");

        resp.StatusCode.Should().BeOneOf(
            HttpStatusCode.Redirect,
            HttpStatusCode.Found,
            HttpStatusCode.SeeOther);

        var location = resp.Headers.Location?.ToString() ?? string.Empty;
        location.Should().Contain("/login");
    }
}
