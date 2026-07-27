using FluentAssertions;
using redb.Identity.Core.Services;
using Xunit;

namespace redb.Identity.Tests.Security;

/// <summary>
/// Z7 phase 1 — SSRF guard for URLs that arrive from outside (a client's <c>jwks_uri</c>,
/// later a JAR <c>request_uri</c>).
/// <para>
/// These are security tests, not style tests. The server sits inside the perimeter and the URL
/// is chosen by someone else, so a missing check here turns an authorization request into a probe
/// of the internal network — most sharply at <c>169.254.169.254</c>, the cloud metadata address
/// that hands instance credentials to anything able to reach it.
/// </para>
/// <para>
/// If one of these ever goes red, the fix is in the guard — never in the test.
/// </para>
/// </summary>
public sealed class OutboundUrlGuardTests
{
    private static OutboundUrlGuard.Rejection Check(string? url, bool requireHttps = true, bool allowPrivate = false)
        => OutboundUrlGuard.ValidateAsync(url, requireHttps, allowPrivate).AsTask().GetAwaiter().GetResult();

    // ── shape ────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("/relative/path")]
    [InlineData("not a url")]
    public void Rejects_non_absolute(string? url)
        => Check(url).Should().Be(OutboundUrlGuard.Rejection.NotAbsolute);

    [Theory]
    [InlineData("file:///etc/passwd")]
    [InlineData("ftp://example.com/keys")]
    [InlineData("gopher://example.com/")]
    public void Rejects_non_http_schemes(string url)
        => Check(url).Should().Be(OutboundUrlGuard.Rejection.SchemeNotAllowed);

    [Fact]
    public void Rejects_plain_http_when_https_required()
        => Check("http://example.com/jwks").Should().Be(OutboundUrlGuard.Rejection.HttpsRequired);

    [Fact]
    public void Allows_plain_http_when_explicitly_permitted()
        => Check("http://example.com/jwks", requireHttps: false)
            .Should().Be(OutboundUrlGuard.Rejection.None);

    // ── the actual SSRF targets ──────────────────────────────────────────────

    [Theory]
    [InlineData("https://169.254.169.254/latest/meta-data/")]   // AWS/GCP/Azure metadata — the crown jewels
    [InlineData("https://127.0.0.1/jwks")]                      // loopback
    [InlineData("https://localhost/jwks")]                      // loopback by name
    [InlineData("https://10.0.0.5/jwks")]                       // RFC 1918
    [InlineData("https://192.168.1.1/jwks")]                    // RFC 1918
    [InlineData("https://172.16.0.1/jwks")]                     // RFC 1918 lower bound
    [InlineData("https://172.31.255.254/jwks")]                 // RFC 1918 upper bound
    [InlineData("https://100.64.0.1/jwks")]                     // RFC 6598 CGNAT
    [InlineData("https://0.0.0.0/jwks")]                        // "this network"
    [InlineData("https://[::1]/jwks")]                          // IPv6 loopback
    [InlineData("https://[fd00::1]/jwks")]                      // IPv6 unique-local
    [InlineData("https://[fe80::1]/jwks")]                      // IPv6 link-local
    public void Rejects_internal_targets(string url)
        => Check(url).Should().Be(OutboundUrlGuard.Rejection.PrivateNetworkTarget);

    /// <summary>
    /// <c>::ffff:10.0.0.1</c> is 10.0.0.1 wearing an IPv6 hat. Judging it as an opaque IPv6
    /// address would walk straight past the RFC 1918 check.
    /// </summary>
    [Fact]
    public void Rejects_ipv4_mapped_ipv6_form_of_private_address()
        => Check("https://[::ffff:10.0.0.1]/jwks").Should().Be(OutboundUrlGuard.Rejection.PrivateNetworkTarget);

    /// <summary>172.32.x is NOT in RFC 1918 — the range ends at 172.31. An over-eager check
    /// would reject legitimate public addresses.</summary>
    [Theory]
    [InlineData("https://172.32.0.1/jwks")]
    [InlineData("https://172.15.0.1/jwks")]
    [InlineData("https://8.8.8.8/jwks")]
    public void Allows_public_addresses_adjacent_to_private_ranges(string url)
        => Check(url).Should().Be(OutboundUrlGuard.Rejection.None);

    [Fact]
    public void Allows_internal_targets_when_dev_override_is_set()
        => Check("https://127.0.0.1/jwks", allowPrivate: true)
            .Should().Be(OutboundUrlGuard.Rejection.None);

    /// <summary>The dev override must not smuggle a bad scheme through with it.</summary>
    [Fact]
    public void Dev_override_does_not_relax_scheme_checks()
        => Check("file:///etc/passwd", requireHttps: false, allowPrivate: true)
            .Should().Be(OutboundUrlGuard.Rejection.SchemeNotAllowed);

    [Fact]
    public void Every_rejection_has_a_human_readable_reason()
    {
        foreach (var value in Enum.GetValues<OutboundUrlGuard.Rejection>())
        {
            OutboundUrlGuard.Describe(value).Should().NotBeNullOrWhiteSpace(
                $"rejection '{value}' surfaces in logs and error descriptions");
        }
    }
}
