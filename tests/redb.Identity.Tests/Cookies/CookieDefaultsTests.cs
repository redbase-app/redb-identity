using FluentAssertions;
using redb.Identity.Core.Configuration;
using redb.Identity.Http.Processors;
using Xunit;
using redb.Identity.Contracts.Configuration;

namespace redb.Identity.Tests.Cookies;

/// <summary>
/// G9 — cookie-flag matrix on <see cref="IdentityCookieFormatter.Build"/>.
/// <para>
/// Every identity cookie (session, mfa_state, federation binding) flows through this
/// single formatter (C9). Any regression here silently drops one of the three flags
/// that keep browser cookies safe — <c>HttpOnly</c> (no JS theft), <c>Secure</c> (no
/// plaintext leakage), <c>SameSite</c> (CSRF). The tests pin the exact emitted
/// string to catch the usual footguns:
/// <list type="bullet">
///   <item><c>__Host-</c> prefix only applied when <c>secure=true</c> (RFC 6265bis §4.1.3.2
///   — the prefix REQUIRES <c>Secure</c>, browsers silently drop otherwise);</item>
///   <item><c>HttpOnly</c> is always emitted (no opt-out);</item>
///   <item><c>Path=/</c> is always emitted (required by <c>__Host-</c>);</item>
///   <item><c>Max-Age=0</c> produces a clearing cookie (logout contract);</item>
///   <item><c>SameSite=None</c> forces <c>Secure</c> for modern browsers (cookie is
///   cross-site; <c>None</c>+not-Secure is rejected).</item>
/// </list>
/// </para>
/// </summary>
public sealed class CookieDefaultsTests
{
    [Fact]
    public void Build_SecureTrue_HostPrefixTrue_AppliesHostPrefix()
    {
        var s = IdentityCookieFormatter.Build(
            "redb.identity.session", "VALUE",
            maxAgeSeconds: 3600,
            secure: true,
            sameSite: CookieSameSiteMode.Lax,
            useHostPrefix: true);

        s.Should().StartWith("__Host-redb.identity.session=VALUE",
            "the __Host- prefix MUST be applied when secure=true and useHostPrefix=true. " +
            "Without it, the server advertises ambient-scope cookies (subdomain-shareable, " +
            "path-overridable) which break the same-origin assumption the session lease " +
            "is built on.");
        s.Should().Contain("; Path=/");
        s.Should().Contain("; Max-Age=3600");
        s.Should().Contain("; HttpOnly");
        s.Should().Contain("; Secure");
        s.Should().Contain("; SameSite=Lax");
    }

    [Fact]
    public void Build_SecureFalse_HostPrefixDropped()
    {
        // Over plain http, emitting a __Host- cookie would be silently dropped by the
        // browser (RFC 6265bis §4.1.3.2 requires Secure). The formatter must fall back
        // to the bare name rather than pretending — otherwise the user appears
        // perpetually logged out in local dev / behind TLS-terminating proxies that
        // advertise http upstream.
        var s = IdentityCookieFormatter.Build(
            "redb.identity.session", "VALUE",
            maxAgeSeconds: 3600,
            secure: false,
            sameSite: CookieSameSiteMode.Lax,
            useHostPrefix: true);

        s.Should().StartWith("redb.identity.session=VALUE");
        s.Should().NotStartWith("__Host-");
        s.Should().NotContain("; Secure");
        s.Should().Contain("; HttpOnly",
            "HttpOnly is unconditional — C9 forbids any code path that emits a JS-readable " +
            "session cookie.");
    }

    [Theory]
    [InlineData(CookieSameSiteMode.Strict, "Strict")]
    [InlineData(CookieSameSiteMode.Lax, "Lax")]
    [InlineData(CookieSameSiteMode.None, "None")]
    public void Build_EmitsCanonicalSameSiteToken(CookieSameSiteMode mode, string expected)
    {
        var s = IdentityCookieFormatter.Build(
            "c", "v", maxAgeSeconds: 60, secure: true, sameSite: mode, useHostPrefix: false);

        s.Should().Contain($"; SameSite={expected}",
            "SameSite token must be the RFC-precise casing; lowercase / misspelled tokens " +
            "are accepted by some browsers but rejected by Safari — producing silent " +
            "session drop in cross-browser tests.");
    }

    [Fact]
    public void Build_MaxAgeZero_EmitsClearingCookie()
    {
        // Logout / ClearSessionCookie / ClearMfaStateCookieOnSuccess all route through
        // Build with maxAgeSeconds=0. The header MUST include Max-Age=0 so browsers
        // treat this as a delete directive (RFC 6265 §5.2.2).
        var s = IdentityCookieFormatter.Build(
            "c", "", maxAgeSeconds: 0, secure: true,
            sameSite: CookieSameSiteMode.Lax, useHostPrefix: false);

        s.Should().Contain("; Max-Age=0",
            "logout path emits maxAgeSeconds=0 which must surface as Max-Age=0 — the " +
            "browser relies on this to evict the session cookie. A regression that " +
            "omits Max-Age entirely would leave the cookie in the jar past logout.");
    }

    [Fact]
    public void Build_EmptyName_Throws()
    {
        // Defensive: a bug in a caller that supplies an empty cookie name would produce
        // an invalid Set-Cookie header ("=value; …") which Kestrel would silently swallow.
        // The formatter rejects it at the seam.
        var act = () => IdentityCookieFormatter.Build(
            "", "v", 60, secure: true, sameSite: CookieSameSiteMode.Lax);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Candidates_ReturnsPrefixedAndBareForReaderMatching()
    {
        var (prefixed, bare) = IdentityCookieFormatter.Candidates("redb.identity.session");

        prefixed.Should().Be("__Host-redb.identity.session");
        bare.Should().Be("redb.identity.session");

        // Readers consult Candidates so an in-progress rollout (http behind TLS proxy
        // still emitting bare, https-direct now emitting __Host-) continues to verify
        // both forms. A regression that returns only one breaks zero-downtime rollout.
    }
}
