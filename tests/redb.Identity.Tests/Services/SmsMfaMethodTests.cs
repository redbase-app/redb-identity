using FluentAssertions;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using Xunit;

namespace redb.Identity.Tests.Services;

/// <summary>
/// Unit tests for <see cref="SmsMfaMethod"/>:
/// phone normalization, masking, setup result, verify against MfaState OTP.
/// </summary>
public sealed class SmsMfaMethodTests
{
    private readonly InMemoryServerSideOtpStore _otpStore = new();
    private readonly SmsMfaMethod _sut;

    public SmsMfaMethodTests()
    {
        _sut = new SmsMfaMethod(_otpStore);
    }

    [Fact]
    public void MethodId_IsSms()
    {
        _sut.MethodId.Should().Be("sms");
    }

    // ── NormalizePhone ──

    [Theory]
    [InlineData("+79991234567", "+79991234567")]
    [InlineData("79991234567", "+79991234567")]
    [InlineData("+7 (999) 123-45-67", "+79991234567")]
    [InlineData("8 999 123 45 67", "+89991234567")]
    public void NormalizePhone_ValidInput_ReturnsE164(string input, string expected)
    {
        SmsMfaMethod.NormalizePhone(input).Should().Be(expected);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("123")]                 // too short
    [InlineData("+1234567890123456789")] // too long
    [InlineData("not-a-phone")]
    public void NormalizePhone_InvalidInput_ReturnsNull(string input)
    {
        SmsMfaMethod.NormalizePhone(input).Should().BeNull();
    }

    // ── MaskPhone ──

    [Theory]
    [InlineData("+79991234567", "+7***4567")]
    [InlineData("+15551234567", "+1***4567")]
    [InlineData("79991234567", "7***4567")]
    public void MaskPhone_ReturnsMasked(string input, string expected)
    {
        SmsMfaMethod.MaskPhone(input).Should().Be(expected);
    }

    [Fact]
    public void MaskPhone_TooShort_ReturnsAsterisks()
    {
        SmsMfaMethod.MaskPhone("123").Should().Be("****");
    }

    // ── SetupAsync ──

    [Fact]
    public async Task Initiate_ValidPhone_ReturnsDestinationAndMasked_NoMutation()
    {
        var initiation = await _sut.InitiateSetupAsync("alice", "+79991234567");

        initiation.MethodId.Should().Be("sms");
        initiation.Destination.Should().Be("+79991234567");
        initiation.ClientResult.Extra.Should().NotBeNull();
        initiation.ClientResult.Extra!["masked_phone"].Should().Be("+7***4567");
    }

    [Fact]
    public async Task Initiate_NullDestination_ReturnsError()
    {
        var initiation = await _sut.InitiateSetupAsync("alice", null);

        initiation.Destination.Should().BeNull();
        initiation.ClientResult.Extra.Should().NotBeNull();
        initiation.ClientResult.Extra!.Should().ContainKey("error");
    }

    [Fact]
    public async Task Initiate_InvalidPhone_ReturnsError()
    {
        var initiation = await _sut.InitiateSetupAsync("alice", "abc");

        initiation.Destination.Should().BeNull();
        initiation.ClientResult.Extra.Should().NotBeNull();
        initiation.ClientResult.Extra!.Should().ContainKey("error");
    }

    // ── VerifyAsync ──

    [Fact]
    public async Task Verify_MatchingCode_ReturnsTrue()
    {
        var props = new MfaProps { SmsPhone = "+79991234567", SmsConfirmed = true };
        var jti = _otpStore.Seed(1, "sms", "123456");
        var state = new MfaState { UserId = 1, OtpMethod = "sms", OtpJti = jti };

        (await _sut.VerifyAsync(props, "123456", state)).Should().BeTrue();
    }

    [Fact]
    public async Task Verify_WrongCode_ReturnsFalse()
    {
        var props = new MfaProps { SmsPhone = "+79991234567", SmsConfirmed = true };
        var jti = _otpStore.Seed(1, "sms", "123456");
        var state = new MfaState { UserId = 1, OtpMethod = "sms", OtpJti = jti };

        (await _sut.VerifyAsync(props, "654321", state)).Should().BeFalse();
    }

    [Fact]
    public async Task Verify_NullState_ReturnsFalse()
    {
        var props = new MfaProps { SmsPhone = "+79991234567", SmsConfirmed = true };
        (await _sut.VerifyAsync(props, "123456", state: null)).Should().BeFalse();
    }

    [Fact]
    public async Task Verify_WrongMethodInState_ReturnsFalse()
    {
        var props = new MfaProps { SmsPhone = "+79991234567", SmsConfirmed = true };
        var jti = _otpStore.Seed(1, "email", "123456");
        var state = new MfaState { UserId = 1, OtpMethod = "email", OtpJti = jti };

        (await _sut.VerifyAsync(props, "123456", state)).Should().BeFalse();
    }

    [Fact]
    public async Task ConfirmAndApply_ValidCode_AppliesPhoneAndConfirms()
    {
        var props = new MfaProps();
        var initiation = await _sut.InitiateSetupAsync("alice", "+79991234567");
        var jti = _otpStore.Seed(1, "sms", "654321");
        var state = new MfaState { UserId = 1, OtpMethod = "sms", OtpJti = jti };

        var ok = await _sut.ConfirmAndApplyAsync(props, initiation, "654321", state);

        ok.Should().BeTrue();
        props.SmsPhone.Should().Be("+79991234567");
        props.SmsConfirmed.Should().BeTrue();
    }

    [Fact]
    public async Task ConfirmAndApply_InvalidCode_LeavesPropsUnchanged()
    {
        var props = new MfaProps();
        var initiation = await _sut.InitiateSetupAsync("alice", "+79991234567");
        var jti = _otpStore.Seed(1, "sms", "654321");
        var state = new MfaState { UserId = 1, OtpMethod = "sms", OtpJti = jti };

        var ok = await _sut.ConfirmAndApplyAsync(props, initiation, "000000", state);

        ok.Should().BeFalse();
        props.SmsPhone.Should().BeNull();
        props.SmsConfirmed.Should().BeFalse();
    }
}
