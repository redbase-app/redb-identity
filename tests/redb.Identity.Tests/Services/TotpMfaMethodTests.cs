using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using OtpNet;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using Xunit;

namespace redb.Identity.Tests.Services;

/// <summary>
/// Unit tests for <see cref="TotpMfaMethod"/>:
/// TOTP setup (QR URI, secret generation), confirm, and verify operations.
/// Uses real DataProtection with ephemeral key ring — no mocks needed.
/// </summary>
public sealed class TotpMfaMethodTests
{
    private static (TotpMfaMethod method, MfaSecretProtector protector) Create(string issuer = "TestApp")
    {
        var dpProvider = DataProtectionProvider.Create("redb-identity-tests");
        var protector = new MfaSecretProtector(dpProvider);
        var method = new TotpMfaMethod(protector, issuer);
        return (method, protector);
    }

    private static string GenerateValidCode(string base32Secret)
    {
        var key = Base32Encoding.ToBytes(base32Secret);
        var totp = new Totp(key, step: 30, totpSize: 6);
        return totp.ComputeTotp();
    }

    [Fact]
    public async Task InitiateSetupAsync_GeneratesSecretAndQrUri_DoesNotMutateProps()
    {
        var (method, protector) = Create("MyIssuer");

        var initiation = await method.InitiateSetupAsync("alice");
        var result = initiation.ClientResult;

        result.MethodId.Should().Be("totp");
        result.SecretBase32.Should().NotBeNullOrEmpty();
        result.SecretBase32!.Length.Should().BeGreaterOrEqualTo(16, "20-byte key → 32 base32 chars");
        result.QrUri.Should().StartWith("otpauth://totp/");
        result.QrUri.Should().Contain("MyIssuer");
        result.QrUri.Should().Contain("alice");
        result.QrUri.Should().Contain($"secret={result.SecretBase32}");
        result.QrUri.Should().Contain("digits=6");
        result.QrUri.Should().Contain("period=30");

        // B5: candidate secret travels in initiation.EncryptedSecret, NOT in props.
        initiation.EncryptedSecret.Should().NotBeNullOrEmpty();
        initiation.EncryptedSecret.Should().NotBe(result.SecretBase32, "secret must be encrypted in token");
        protector.Unprotect(initiation.EncryptedSecret!).Should().Be(result.SecretBase32);
    }

    [Fact]
    public async Task InitiateSetupAsync_EncodesSpecialCharsInUri()
    {
        var (method, _) = Create("My App & Co.");

        var initiation = await method.InitiateSetupAsync("user@example.com");

        initiation.ClientResult.QrUri.Should().Contain(Uri.EscapeDataString("My App & Co."));
        initiation.ClientResult.QrUri.Should().Contain(Uri.EscapeDataString("user@example.com"));
    }

    [Fact]
    public async Task ConfirmAndApplyAsync_ValidCode_WritesSecretAndConfirms()
    {
        var (method, _) = Create();
        var props = new MfaProps();

        var initiation = await method.InitiateSetupAsync("alice");
        var code = GenerateValidCode(initiation.ClientResult.SecretBase32!);

        var confirmed = await method.ConfirmAndApplyAsync(props, initiation, code);

        confirmed.Should().BeTrue();
        props.TotpSecret.Should().Be(initiation.EncryptedSecret, "secret applied on success");
        props.TotpConfirmed.Should().BeTrue();
    }

    [Fact]
    public async Task ConfirmAndApplyAsync_InvalidCode_LeavesPropsUnchanged()
    {
        var (method, _) = Create();
        var props = new MfaProps();

        var initiation = await method.InitiateSetupAsync("alice");

        var confirmed = await method.ConfirmAndApplyAsync(props, initiation, "000000");

        confirmed.Should().BeFalse();
        props.TotpSecret.Should().BeNull("invalid code must not apply secret");
        props.TotpConfirmed.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyAsync_ValidCode_ReturnsTrue()
    {
        var (method, _) = Create();
        var props = new MfaProps();

        var initiation = await method.InitiateSetupAsync("alice");
        // Stage the secret directly to avoid Confirm seeding LastTotpStep with the current step
        // (which would make a same-step Verify trip the replay guard).
        props.TotpSecret = initiation.EncryptedSecret;

        var code = GenerateValidCode(initiation.ClientResult.SecretBase32!);
        var verified = await method.VerifyAsync(props, code);

        verified.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyAsync_InvalidCode_ReturnsFalse()
    {
        var (method, _) = Create();
        var props = new MfaProps();

        var initiation = await method.InitiateSetupAsync("alice");
        props.TotpSecret = initiation.EncryptedSecret;

        var verified = await method.VerifyAsync(props, "999999");
        verified.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyAsync_EmptyCode_ReturnsFalse()
    {
        var (method, _) = Create();
        var props = new MfaProps();
        var initiation = await method.InitiateSetupAsync("alice");
        props.TotpSecret = initiation.EncryptedSecret;

        (await method.VerifyAsync(props, "")).Should().BeFalse();
        (await method.VerifyAsync(props, null!)).Should().BeFalse();
    }

    [Fact]
    public async Task VerifyAsync_NoSecretInProps_ReturnsFalse()
    {
        var (method, _) = Create();
        var props = new MfaProps(); // no setup done

        (await method.VerifyAsync(props, "123456")).Should().BeFalse();
    }

    [Fact]
    public async Task InitiateSetupAsync_GeneratesIndependentSecretsEachCall()
    {
        var (method, _) = Create();

        var setup1 = await method.InitiateSetupAsync("alice");
        var setup2 = await method.InitiateSetupAsync("alice");

        setup1.ClientResult.SecretBase32.Should().NotBe(setup2.ClientResult.SecretBase32,
            "each initiation generates a new random secret");
        setup1.EncryptedSecret.Should().NotBe(setup2.EncryptedSecret);
    }
}
