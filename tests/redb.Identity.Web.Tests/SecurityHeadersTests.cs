using System.Net.Http;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace redb.Identity.Web.Tests;

/// <summary>
/// F-2.5 regression: production-grade security response headers must be present
/// on every response from the BFF.
/// </summary>
public sealed class SecurityHeadersTests : IClassFixture<WebHostFixture>
{
    private readonly WebHostFixture _factory;

    public SecurityHeadersTests(WebHostFixture factory) { _factory = factory; }

    [Fact]
    public async Task Health_endpoint_emits_security_headers()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var resp = await client.GetAsync("/health");
        resp.EnsureSuccessStatusCode();

        resp.Headers.Should().ContainKey("Content-Security-Policy");
        resp.Headers.GetValues("Content-Security-Policy").Should()
            .ContainSingle().Which.Should().Contain("default-src 'self'");

        resp.Headers.Should().ContainKey("X-Frame-Options");
        resp.Headers.GetValues("X-Frame-Options").Should().ContainSingle().Which.Should().Be("DENY");

        resp.Headers.Should().ContainKey("X-Content-Type-Options");
        resp.Headers.GetValues("X-Content-Type-Options").Should().ContainSingle().Which.Should().Be("nosniff");

        resp.Headers.Should().ContainKey("Referrer-Policy");
        resp.Headers.Should().ContainKey("Permissions-Policy");
        resp.Headers.Should().ContainKey("Cross-Origin-Opener-Policy");
    }
}
