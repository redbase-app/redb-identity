using FluentAssertions;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using Xunit;

namespace redb.Identity.Tests.Services;

/// <summary>
/// Unit tests for <see cref="EmailMfaMethod"/>:
/// email normalization, masking, setup, verify against MfaState OTP.
/// </summary>
public sealed class EmailMfaMethodTests
{
    private readonly InMemoryServerSideOtpStore _otpStore = new();
    private readonly EmailMfaMethod _sut;

    public EmailMfaMethodTests()
    {
        _sut = new EmailMfaMethod(_otpStore);
    }

    [Fact]
    public void MethodId_IsEmail()
    {
        _sut.MethodId.Should().Be("email");
    }

    // ── NormalizeEmail ──

    [Theory]
    [InlineData("user@example.com", "user@example.com")]
    [InlineData("USER@Example.COM", "user@example.com")]
    [InlineData("  user@example.com  ", "user@example.com")]
    public void NormalizeEmail_ValidInput_ReturnsLowercaseTrimmed(string input, string expected)
    {
        EmailMfaMethod.NormalizeEmail(input).Should().Be(expected);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("noatsign")]
    [InlineData("@example.com")]
    [InlineData("user@")]
    [InlineData("user@nodot")]
    [InlineData("a@b")]      // too short
    public void NormalizeEmail_InvalidInput_ReturnsNull(string input)
    {
        EmailMfaMethod.NormalizeEmail(input).Should().BeNull();
    }

    // ── MaskEmail ──

    [Theory]
    [InlineData("user@example.com", "u***@example.com")]
    [InlineData("alice@redb.io", "a***@redb.io")]
    [InlineData("a@b.com", "*@b.com")]
    public void MaskEmail_ReturnsMasked(string input, string expected)
    {
        EmailMfaMethod.MaskEmail(input).Should().Be(expected);
    }

    // ── SetupAsync ──

    [Fact]
    public async Task Initiate_ValidEmail_NormalizesAndReturnsMasked()
    {
        var initiation = await _sut.InitiateSetupAsync("alice", "Alice@Example.com");

        initiation.MethodId.Should().Be("email");
        initiation.Destination.Should().Be("alice@example.com");
        initiation.ClientResult.Extra.Should().NotBeNull();
        initiation.ClientResult.Extra!["masked_email"].Should().Be("a***@example.com");
    }

    [Fact]
    public async Task Initiate_InvalidEmail_ReturnsError()
    {
        var initiation = await _sut.InitiateSetupAsync("alice", "not-an-email");

        initiation.Destination.Should().BeNull();
        initiation.ClientResult.Extra!.Should().ContainKey("error");
    }

    [Fact]
    public async Task Initiate_NullDestination_ReturnsError()
    {
        var initiation = await _sut.InitiateSetupAsync("alice", null);

        initiation.Destination.Should().BeNull();
        initiation.ClientResult.Extra!.Should().ContainKey("error");
    }

    // ── VerifyAsync ──

    [Fact]
    public async Task Verify_MatchingCode_ReturnsTrue()
    {
        var props = new MfaProps { OtpEmail = "alice@example.com", EmailConfirmed = true };
        var jti = _otpStore.Seed(1, "email", "123456");
        var state = new MfaState { UserId = 1, OtpMethod = "email", OtpJti = jti };

        (await _sut.VerifyAsync(props, "123456", state)).Should().BeTrue();
    }

    [Fact]
    public async Task Verify_WrongCode_ReturnsFalse()
    {
        var props = new MfaProps { OtpEmail = "alice@example.com", EmailConfirmed = true };
        var jti = _otpStore.Seed(1, "email", "123456");
        var state = new MfaState { UserId = 1, OtpMethod = "email", OtpJti = jti };

        (await _sut.VerifyAsync(props, "999999", state)).Should().BeFalse();
    }

    [Fact]
    public async Task Verify_NullState_ReturnsFalse()
    {
        var props = new MfaProps { OtpEmail = "alice@example.com", EmailConfirmed = true };
        (await _sut.VerifyAsync(props, "123456", state: null)).Should().BeFalse();
    }

    [Fact]
    public async Task Verify_WrongMethodInState_ReturnsFalse()
    {
        var props = new MfaProps { OtpEmail = "alice@example.com", EmailConfirmed = true };
        var jti = _otpStore.Seed(1, "sms", "123456");
        var state = new MfaState { UserId = 1, OtpMethod = "sms", OtpJti = jti };

        (await _sut.VerifyAsync(props, "123456", state)).Should().BeFalse();
    }

    [Fact]
    public async Task ConfirmAndApply_ValidCode_AppliesEmailAndConfirms()
    {
        var props = new MfaProps();
        var initiation = await _sut.InitiateSetupAsync("alice", "Alice@Example.com");
        var jti = _otpStore.Seed(1, "email", "111222");
        var state = new MfaState { UserId = 1, OtpMethod = "email", OtpJti = jti };

        var ok = await _sut.ConfirmAndApplyAsync(props, initiation, "111222", state);

        ok.Should().BeTrue();
        props.OtpEmail.Should().Be("alice@example.com");
        props.EmailConfirmed.Should().BeTrue();
    }

    [Fact]
    public async Task ConfirmAndApply_InvalidCode_LeavesPropsUnchanged()
    {
        var props = new MfaProps();
        var initiation = await _sut.InitiateSetupAsync("alice", "Alice@Example.com");
        var jti = _otpStore.Seed(1, "email", "111222");
        var state = new MfaState { UserId = 1, OtpMethod = "email", OtpJti = jti };

        var ok = await _sut.ConfirmAndApplyAsync(props, initiation, "000000", state);

        ok.Should().BeFalse();
        props.OtpEmail.Should().BeNull();
        props.EmailConfirmed.Should().BeFalse();
    }
}
