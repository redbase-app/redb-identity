using FluentAssertions;
using redb.Identity.Core.Configuration;
using redb.Identity.Http.Processors;
using Xunit;
using redb.Identity.Contracts.Configuration;

namespace redb.Identity.Tests.Services;

/// <summary>
/// C9 — verifies <see cref="IdentityCookieFormatter"/> emits flag-correct, RFC-compliant
/// Set-Cookie headers for the session and federation-binding cookies.
/// </summary>
public class IdentityCookieFormatterTests
{
    [Fact]
    public void Build_AlwaysIncludes_HttpOnly_Path_MaxAge()
    {
        var header = IdentityCookieFormatter.Build(
            "x", "v", maxAgeSeconds: 60, secure: false, sameSite: CookieSameSiteMode.Lax);

        header.Should().Contain("HttpOnly");
        header.Should().Contain("Path=/");
        header.Should().Contain("Max-Age=60");
    }

    [Fact]
    public void Build_OmitsSecure_WhenSecureFalse()
    {
        var header = IdentityCookieFormatter.Build(
            "x", "v", maxAgeSeconds: 60, secure: false, sameSite: CookieSameSiteMode.Lax);

        header.Should().NotContain("Secure");
    }

    [Fact]
    public void Build_AppendsSecure_WhenSecureTrue()
    {
        var header = IdentityCookieFormatter.Build(
            "x", "v", maxAgeSeconds: 60, secure: true, sameSite: CookieSameSiteMode.Lax);

        header.Should().Contain("; Secure");
    }

    [Theory]
    [InlineData(CookieSameSiteMode.Strict, "SameSite=Strict")]
    [InlineData(CookieSameSiteMode.Lax, "SameSite=Lax")]
    [InlineData(CookieSameSiteMode.None, "SameSite=None")]
    public void Build_EmitsConfiguredSameSiteToken(CookieSameSiteMode mode, string expected)
    {
        var header = IdentityCookieFormatter.Build(
            "x", "v", maxAgeSeconds: 60, secure: true, sameSite: mode);

        header.Should().Contain(expected);
    }

    [Fact]
    public void Build_AppliesHostPrefix_WhenSecureAndOptedIn()
    {
        var header = IdentityCookieFormatter.Build(
            "redb.identity.session", "v",
            maxAgeSeconds: 60, secure: true, sameSite: CookieSameSiteMode.Lax,
            useHostPrefix: true);

        header.Should().StartWith("__Host-redb.identity.session=v");
    }

    [Fact]
    public void Build_DropsHostPrefix_OverHttp()
    {
        // __Host- requires Secure (RFC 6265bis §4.1.3.2). Over plain http we silently
        // strip the prefix so the browser doesn't reject the cookie.
        var header = IdentityCookieFormatter.Build(
            "redb.identity.session", "v",
            maxAgeSeconds: 60, secure: false, sameSite: CookieSameSiteMode.Lax,
            useHostPrefix: true);

        header.Should().StartWith("redb.identity.session=v");
        header.Should().NotContain("__Host-");
    }

    [Fact]
    public void Build_OmitsHostPrefix_ByDefault()
    {
        var header = IdentityCookieFormatter.Build(
            "redb.identity.session", "v",
            maxAgeSeconds: 60, secure: true, sameSite: CookieSameSiteMode.Lax);

        header.Should().StartWith("redb.identity.session=v");
        header.Should().NotContain("__Host-");
    }

    [Fact]
    public void Build_MaxAgeZero_ShapesADeleteHeader()
    {
        // Browsers delete a cookie by name+path+domain when Max-Age=0; the rest of the
        // attributes don't have to match exactly, but keeping flags identical to the Set
        // is the safest portable approach.
        var header = IdentityCookieFormatter.Build(
            "x", value: string.Empty,
            maxAgeSeconds: 0, secure: true, sameSite: CookieSameSiteMode.Lax);

        header.Should().StartWith("x=");
        header.Should().Contain("Max-Age=0");
    }

    [Fact]
    public void Candidates_ReturnsBothPrefixedAndBareNames()
    {
        var (prefixed, bare) = IdentityCookieFormatter.Candidates("redb.identity.session");

        prefixed.Should().Be("__Host-redb.identity.session");
        bare.Should().Be("redb.identity.session");
    }

    [Fact]
    public void Build_RejectsEmptyName()
    {
        var act = () => IdentityCookieFormatter.Build(
            "", "v", maxAgeSeconds: 60, secure: true, sameSite: CookieSameSiteMode.Lax);

        act.Should().Throw<ArgumentException>();
    }
}
