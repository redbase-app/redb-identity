using FluentAssertions;
using redb.Identity.Core.Configuration;
using Xunit;

namespace redb.Identity.Tests.Configuration;

/// <summary>
/// MFA-3 fail-fast unit tests for <see cref="IdentityWebAuthnOptions.Validate"/>. The
/// validator is invoked from <c>RedbIdentityServiceExtensions.AddRedbIdentity</c> when
/// <see cref="IdentityWebAuthnOptions.Enabled"/> is <c>true</c>; the goal of these tests
/// is to guarantee a misconfigured deployment never reaches the first-credential
/// registration with broken settings (since changing RpId after credentials exist
/// invalidates them all).
/// </summary>
public sealed class IdentityWebAuthnOptionsTests
{
    private static IdentityWebAuthnOptions Valid() => new()
    {
        Enabled = true,
        RpId = "auth.example.com",
        Origins = { "https://auth.example.com" },
    };

    [Fact]
    public void Validate_PassesForMinimalValidConfig()
    {
        var act = () => Valid().Validate();
        act.Should().NotThrow();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_ThrowsOnBlankRpId(string? rpId)
    {
        var o = Valid();
        o.RpId = rpId;
        var act = () => o.Validate();
        act.Should().Throw<InvalidOperationException>().WithMessage("*RpId is required*");
    }

    [Theory]
    [InlineData("https://auth.example.com")] // includes scheme
    [InlineData("auth.example.com/path")]    // includes path
    public void Validate_ThrowsOnRpIdWithSchemeOrPath(string rpId)
    {
        var o = Valid();
        o.RpId = rpId;
        var act = () => o.Validate();
        act.Should().Throw<InvalidOperationException>().WithMessage("*bare host name*");
    }

    [Fact]
    public void Validate_ThrowsOnEmptyOrigins()
    {
        var o = Valid();
        o.Origins.Clear();
        var act = () => o.Validate();
        act.Should().Throw<InvalidOperationException>().WithMessage("*Origins*at least one*");
    }

    [Theory]
    [InlineData("auth.example.com")]              // missing scheme
    [InlineData("ftp://auth.example.com")]        // wrong scheme
    [InlineData("http://auth.example.com")]       // http on non-localhost rejected
    public void Validate_ThrowsOnInvalidOrigin(string origin)
    {
        var o = Valid();
        o.Origins.Clear();
        o.Origins.Add(origin);
        var act = () => o.Validate();
        act.Should().Throw<InvalidOperationException>().WithMessage("*absolute https*");
    }

    [Fact]
    public void Validate_AcceptsHttpLocalhost()
    {
        var o = Valid();
        o.Origins.Add("http://localhost:5000");
        var act = () => o.Validate();
        act.Should().NotThrow();
    }

    [Fact]
    public void Validate_ThrowsOnNonPositiveTimeout()
    {
        var o = Valid();
        o.TimeoutMs = 0;
        var act = () => o.Validate();
        act.Should().Throw<InvalidOperationException>().WithMessage("*TimeoutMs*");
    }

    [Fact]
    public void Validate_ThrowsOnChallengeTtlShorterThanTimeout()
    {
        var o = Valid();
        o.TimeoutMs = 60_000;
        o.ChallengeTtlSeconds = 30; // < 60
        var act = () => o.Validate();
        act.Should().Throw<InvalidOperationException>().WithMessage("*ChallengeTtlSeconds*");
    }

    [Theory]
    [InlineData("optional")]
    [InlineData("never")]
    [InlineData("REQUIRED")]
    public void Validate_ThrowsOnInvalidUserVerification(string uv)
    {
        var o = Valid();
        o.UserVerification = uv;
        var act = () => o.Validate();
        act.Should().Throw<InvalidOperationException>().WithMessage("*UserVerification*");
    }

    [Fact]
    public void Validate_ThrowsOnInvalidAttestation()
    {
        var o = Valid();
        o.Attestation = "magic";
        var act = () => o.Validate();
        act.Should().Throw<InvalidOperationException>().WithMessage("*Attestation*");
    }

    [Fact]
    public void Validate_ThrowsOnInvalidAaguidGuid()
    {
        var o = Valid();
        o.AaguidBlocklist = new List<string> { "not-a-guid" };
        var act = () => o.Validate();
        act.Should().Throw<InvalidOperationException>().WithMessage("*AaguidBlocklist*not a valid GUID*");
    }

    [Fact]
    public void Validate_AcceptsValidAaguidGuid()
    {
        var o = Valid();
        o.AaguidBlocklist = new List<string> { Guid.NewGuid().ToString() };
        var act = () => o.Validate();
        act.Should().NotThrow();
    }
}
