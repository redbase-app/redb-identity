using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using redb.Identity.Core.Services;
using Xunit;

namespace redb.Identity.Tests.Services;

/// <summary>
/// Unit tests for <see cref="MfaSecretProtector"/>:
/// DataProtection-based encrypt/decrypt for TOTP secrets (no TTL).
/// No PostgreSQL required — ephemeral key ring only.
/// </summary>
public sealed class MfaSecretProtectorTests
{
    private static MfaSecretProtector CreateProtector()
    {
        var dpProvider = DataProtectionProvider.Create("redb-identity-tests");
        return new MfaSecretProtector(dpProvider);
    }

    [Fact]
    public void Protect_Unprotect_RoundTrip()
    {
        var protector = CreateProtector();
        var secret = "JBSWY3DPEHPK3PXP";

        var encrypted = protector.Protect(secret);
        encrypted.Should().NotBeNullOrEmpty();
        encrypted.Should().NotBe(secret, "must be encrypted");

        var restored = protector.Unprotect(encrypted);
        restored.Should().Be(secret);
    }

    [Fact]
    public void Protect_DifferentInputs_ProduceDifferentOutputs()
    {
        var protector = CreateProtector();

        var a = protector.Protect("SECRET_A");
        var b = protector.Protect("SECRET_B");

        a.Should().NotBe(b);
    }

    [Fact]
    public void Unprotect_NullOrEmpty_ReturnsNull()
    {
        var protector = CreateProtector();

        protector.Unprotect(null!).Should().BeNull();
        protector.Unprotect("").Should().BeNull();
    }

    [Fact]
    public void Unprotect_TamperedData_ReturnsNull()
    {
        var protector = CreateProtector();
        var encrypted = protector.Protect("MYSECRET");

        var chars = encrypted.ToCharArray();
        chars[encrypted.Length / 2] = (char)(chars[encrypted.Length / 2] ^ 0xFF);
        var tampered = new string(chars);

        protector.Unprotect(tampered).Should().BeNull("tampered data must be rejected");
    }

    [Fact]
    public void Unprotect_GarbageInput_ReturnsNull()
    {
        var protector = CreateProtector();
        protector.Unprotect("not-valid-base64!!!").Should().BeNull();
        protector.Unprotect("AAAA").Should().BeNull();
    }

    [Fact]
    public void DifferentInstances_SameKeyRing_CanDecrypt()
    {
        var dpProvider = DataProtectionProvider.Create("redb-mfa-secret-shared");
        var p1 = new MfaSecretProtector(dpProvider);
        var p2 = new MfaSecretProtector(dpProvider);

        var encrypted = p1.Protect("SHARED_SECRET");
        var restored = p2.Unprotect(encrypted);

        restored.Should().Be("SHARED_SECRET");
    }

    [Fact]
    public void Protect_ThrowsOnNullInput()
    {
        var protector = CreateProtector();
        var act = () => protector.Protect(null!);
        act.Should().Throw<ArgumentNullException>();
    }
}
