using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using OtpNet;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Services;

/// <summary>
/// Unit tests for <see cref="MfaService"/>:
/// Orchestration layer — setup, confirm, verify, lockout, recovery codes, disable, status.
/// Uses mocked IRedbService + real TotpMfaMethod with ephemeral DataProtection.
/// </summary>
public sealed class MfaServiceTests
{
    private readonly IRedbService _redb = Substitute.For<IRedbService>();
    private readonly MfaSecretProtector _secretProtector;
    private readonly MfaStateProtector _stateProtector;
    private readonly TotpMfaMethod _totpMethod;
    private readonly MfaService _sut;

    public MfaServiceTests()
    {
        var dpProvider = DataProtectionProvider.Create("redb-mfa-service-tests");
        _secretProtector = new MfaSecretProtector(dpProvider);
        _stateProtector = new MfaStateProtector(dpProvider);
        _totpMethod = new TotpMfaMethod(_secretProtector);
        _sut = new MfaService(
            _redb,
            new IMfaMethod[] { _totpMethod },
            Array.Empty<IMfaDeliveryChannel>(),
            _stateProtector,
            new MfaSetupTokenProtector(dpProvider),
            Microsoft.Extensions.Options.Options.Create(new redb.Identity.Core.Configuration.RedbIdentityOptions()),
            RecoveryCodePepperProvider.ForTesting(),
            NullLogger<MfaService>.Instance);
    }

    private static string GenerateValidCode(string base32Secret)
    {
        var key = Base32Encoding.ToBytes(base32Secret);
        var totp = new Totp(key, step: 30, totpSize: 6);
        return totp.ComputeTotp();
    }

    private void SetupEmptyQuery()
    {
        MockRedbQuery.Setup(_redb, new List<RedbObject<MfaProps>>());
    }

    private RedbObject<MfaProps> SetupExistingProps(long userId, MfaProps props)
    {
        var obj = new RedbObject<MfaProps>(props) { Id = 100 };
        obj.key = userId;
        MockRedbQuery.Setup(_redb, new List<RedbObject<MfaProps>> { obj });
        return obj;
    }

    // ── IsMfaEnabledAsync ──

    [Fact]
    public async Task IsMfaEnabled_NoProps_ReturnsFalse()
    {
        SetupEmptyQuery();
        (await _sut.IsMfaEnabledAsync(1)).Should().BeFalse();
    }

    [Fact]
    public async Task IsMfaEnabled_EnabledAndConfirmed_ReturnsTrue()
    {
        SetupExistingProps(1, new MfaProps { Enabled = true, TotpConfirmed = true });
        (await _sut.IsMfaEnabledAsync(1)).Should().BeTrue();
    }

    [Fact]
    public async Task IsMfaEnabled_EnabledButNotConfirmed_ReturnsFalse()
    {
        SetupExistingProps(1, new MfaProps { Enabled = true, TotpConfirmed = false });
        (await _sut.IsMfaEnabledAsync(1)).Should().BeFalse();
    }

    // ── GetEnabledMethodsAsync ──

    [Fact]
    public async Task GetEnabledMethods_NoProps_ReturnsEmpty()
    {
        SetupEmptyQuery();
        (await _sut.GetEnabledMethodsAsync(1)).Should().BeEmpty();
    }

    [Fact]
    public async Task GetEnabledMethods_TotpConfirmed_ReturnsTotp()
    {
        SetupExistingProps(1, new MfaProps { Enabled = true, TotpConfirmed = true });
        (await _sut.GetEnabledMethodsAsync(1)).Should().BeEquivalentTo(["totp"]);
    }

    // ── SetupAsync ──

    [Fact]
    public async Task SetupAsync_DoesNotPersist_ReturnsSetupToken()
    {
        SetupEmptyQuery();

        var result = await _sut.SetupAsync(1, "totp", "alice");

        result.MethodId.Should().Be("totp");
        result.SecretBase32.Should().NotBeNullOrEmpty();
        result.QrUri.Should().Contain("alice");
        // B5: Setup must NOT touch the database \u2014 secret travels in setup_token only.
        result.SetupToken.Should().NotBeNullOrEmpty();
        await _redb.DidNotReceive().SaveAsync(Arg.Any<RedbObject<MfaProps>>());
    }

    [Fact]
    public async Task SetupAsync_UnknownMethod_Throws()
    {
        SetupEmptyQuery();
        var act = () => _sut.SetupAsync(1, "sms", "alice");
        await act.Should().ThrowAsync<ArgumentException>().WithMessage("*Unknown MFA method*");
    }

    // ── ConfirmSetupAsync ──

    [Fact]
    public async Task ConfirmSetup_ValidCode_EnablesMfaAndReturnsRecoveryCodes()
    {
        SetupEmptyQuery();

        // Setup first — issues an encrypted setup_token; props are NOT yet saved.
        var setup = await _sut.SetupAsync(1, "totp", "alice");
        setup.SetupToken.Should().NotBeNullOrEmpty();

        // Empty store — confirm path will create the row.
        SetupEmptyQuery();

        var code = GenerateValidCode(setup.SecretBase32!);
        var recoveryCodes = await _sut.ConfirmSetupAsync(1, "totp", code, setup.SetupToken!);

        recoveryCodes.Should().NotBeNull();
        recoveryCodes!.Length.Should().Be(10);
        // Recovery codes must match XXXX-XXXX format
        foreach (var rc in recoveryCodes)
        {
            rc.Should().MatchRegex(@"^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}$");
        }

        var savedObj = (RedbObject<MfaProps>)_redb.ReceivedCalls()
            .First(c => c.GetMethodInfo().Name == "SaveAsync")
            .GetArguments()[0]!;

        savedObj.Props.Enabled.Should().BeTrue();
        savedObj.Props.TotpConfirmed.Should().BeTrue();
        savedObj.Props.DefaultMethod.Should().Be("totp");
        savedObj.Props.RecoveryCodes.Should().HaveCount(10);
        savedObj.Props.FailedAttempts.Should().Be(0);
    }

    [Fact]
    public async Task ConfirmSetup_InvalidCode_ReturnsNull()
    {
        SetupEmptyQuery();
        var setup = await _sut.SetupAsync(1, "totp", "alice");

        SetupEmptyQuery();
        var result = await _sut.ConfirmSetupAsync(1, "totp", "000000", setup.SetupToken!);
        result.Should().BeNull();
    }

    [Fact]
    public async Task ConfirmSetup_InvalidToken_ReturnsNull()
    {
        SetupEmptyQuery();
        var result = await _sut.ConfirmSetupAsync(1, "totp", "123456", "not-a-valid-token");
        result.Should().BeNull();
    }

    // ── VerifyAsync ──

    [Fact]
    public async Task Verify_ValidCode_ReturnsTrueAndResetsAttempts()
    {
        // Setup a confirmed TOTP user
        var base32 = "JBSWY3DPEHPK3PXP";
        var props = new MfaProps
        {
            Enabled = true,
            TotpConfirmed = true,
            TotpSecret = _secretProtector.Protect(base32),
            FailedAttempts = 2
        };
        SetupExistingProps(1, props);

        var code = GenerateValidCode(base32);
        var result = await _sut.VerifyAsync(1, "totp", code);

        result.Should().BeTrue();
        props.FailedAttempts.Should().Be(0);
        props.LastVerifiedAt.Should().NotBeNull();
    }

    [Fact]
    public async Task Verify_InvalidCode_IncrementsFailedAttempts()
    {
        var base32 = "JBSWY3DPEHPK3PXP";
        var props = new MfaProps
        {
            Enabled = true,
            TotpConfirmed = true,
            TotpSecret = _secretProtector.Protect(base32),
            FailedAttempts = 0
        };
        SetupExistingProps(1, props);

        var result = await _sut.VerifyAsync(1, "totp", "000000");

        result.Should().BeFalse();
        props.FailedAttempts.Should().Be(1);
    }

    [Fact]
    public async Task Verify_FifthFailedAttempt_ActivatesLockout()
    {
        var base32 = "JBSWY3DPEHPK3PXP";
        var props = new MfaProps
        {
            Enabled = true,
            TotpConfirmed = true,
            TotpSecret = _secretProtector.Protect(base32),
            FailedAttempts = 4 // next fail = 5th
        };
        SetupExistingProps(1, props);

        var result = await _sut.VerifyAsync(1, "totp", "000000");

        result.Should().BeFalse();
        props.FailedAttempts.Should().Be(5);
        props.LockedUntil.Should().NotBeNull();
        props.LockedUntil!.Value.Should().BeAfter(DateTimeOffset.UtcNow.AddMinutes(14));
    }

    [Fact]
    public async Task Verify_LockedOut_RejectEvenValidCode()
    {
        var base32 = "JBSWY3DPEHPK3PXP";
        var props = new MfaProps
        {
            Enabled = true,
            TotpConfirmed = true,
            TotpSecret = _secretProtector.Protect(base32),
            FailedAttempts = 5,
            LockedUntil = DateTimeOffset.UtcNow.AddMinutes(10)
        };
        SetupExistingProps(1, props);

        var code = GenerateValidCode(base32);
        var result = await _sut.VerifyAsync(1, "totp", code);

        result.Should().BeFalse("locked out users should be rejected");
    }

    [Fact]
    public async Task Verify_NoProps_ReturnsFalse()
    {
        SetupEmptyQuery();
        (await _sut.VerifyAsync(1, "totp", "123456")).Should().BeFalse();
    }

    // ── VerifyRecoveryCodeAsync ──

    [Fact]
    public async Task VerifyRecoveryCode_ValidCode_ReturnsTrueAndConsumesCode()
    {
        var plainCode = "ABCD-EF23";
        var hash = HashCode(plainCode);
        var props = new MfaProps
        {
            Enabled = true,
            TotpConfirmed = true,
            RecoveryCodes = new List<string> { hash, "other-hash" },
            FailedAttempts = 3
        };
        SetupExistingProps(1, props);

        var result = await _sut.VerifyRecoveryCodeAsync(1, plainCode);

        result.Should().BeTrue();
        props.RecoveryCodes.Should().HaveCount(1);
        props.RecoveryCodes.Should().NotContain(hash);
        props.FailedAttempts.Should().Be(0);
        props.LastVerifiedAt.Should().NotBeNull();
    }

    [Fact]
    public async Task VerifyRecoveryCode_NormalizesInput()
    {
        // Code with dashes and mixed case should match
        var plainCode = "ABCD-EF23";
        var hash = HashCode(plainCode);
        var props = new MfaProps
        {
            Enabled = true,
            RecoveryCodes = new List<string> { hash }
        };
        SetupExistingProps(1, props);

        // Send lowercase without dash — should still match after normalization
        var result = await _sut.VerifyRecoveryCodeAsync(1, "abcdef23");
        result.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyRecoveryCode_InvalidCode_ReturnsFalse()
    {
        var props = new MfaProps
        {
            Enabled = true,
            RecoveryCodes = new List<string> { "somehash" }
        };
        SetupExistingProps(1, props);

        (await _sut.VerifyRecoveryCodeAsync(1, "WRONG-CODE")).Should().BeFalse();
    }

    [Fact]
    public async Task VerifyRecoveryCode_NoCodes_ReturnsFalse()
    {
        SetupExistingProps(1, new MfaProps { RecoveryCodes = null });
        (await _sut.VerifyRecoveryCodeAsync(1, "ABCD-EF23")).Should().BeFalse();
    }

    [Fact]
    public async Task VerifyRecoveryCode_EmptyList_ReturnsFalse()
    {
        SetupExistingProps(1, new MfaProps { RecoveryCodes = new List<string>() });
        (await _sut.VerifyRecoveryCodeAsync(1, "ABCD-EF23")).Should().BeFalse();
    }

    // ── DisableAsync ──

    [Fact]
    public async Task Disable_Totp_ClearsAllMfaData()
    {
        var props = new MfaProps
        {
            Enabled = true,
            DefaultMethod = "totp",
            TotpSecret = "encrypted",
            TotpConfirmed = true,
            RecoveryCodes = new List<string> { "hash1" },
            FailedAttempts = 3,
            LockedUntil = DateTimeOffset.UtcNow.AddMinutes(5)
        };
        SetupExistingProps(1, props);

        await _sut.DisableAsync(1, "totp");

        props.Enabled.Should().BeFalse();
        props.TotpSecret.Should().BeNull();
        props.TotpConfirmed.Should().BeFalse();
        props.DefaultMethod.Should().BeNull();
        props.RecoveryCodes.Should().BeNull();
        props.FailedAttempts.Should().Be(0);
        props.LockedUntil.Should().BeNull();
    }

    [Fact]
    public async Task Disable_NoProps_DoesNotThrow()
    {
        SetupEmptyQuery();
        var act = () => _sut.DisableAsync(1, "totp");
        await act.Should().NotThrowAsync();
    }

    // ── GetStatusAsync ──

    [Fact]
    public async Task GetStatus_NoProps_ReturnsDisabledEmpty()
    {
        SetupEmptyQuery();

        var status = await _sut.GetStatusAsync(1);

        status.Enabled.Should().BeFalse();
        status.Methods.Should().BeEmpty();
        status.RecoveryCodesRemaining.Should().Be(0);
    }

    [Fact]
    public async Task GetStatus_EnabledWithTotp_ReturnsCorrectStatus()
    {
        SetupExistingProps(1, new MfaProps
        {
            Enabled = true,
            TotpConfirmed = true,
            RecoveryCodes = new List<string> { "a", "b", "c" }
        });

        var status = await _sut.GetStatusAsync(1);

        status.Enabled.Should().BeTrue();
        status.Methods.Should().BeEquivalentTo(["totp"]);
        status.RecoveryCodesRemaining.Should().Be(3);
    }

    // ── RegenerateRecoveryCodesAsync ──

    [Fact]
    public async Task RegenerateRecoveryCodes_MfaEnabled_ReturnsNewCodes()
    {
        SetupExistingProps(1, new MfaProps
        {
            Enabled = true,
            TotpConfirmed = true,
            RecoveryCodes = new List<string> { "old1", "old2" }
        });

        var codes = await _sut.RegenerateRecoveryCodesAsync(1);

        codes.Should().NotBeNull();
        codes!.Length.Should().Be(10);
        foreach (var code in codes)
        {
            code.Should().MatchRegex(@"^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}$");
        }
    }

    [Fact]
    public async Task RegenerateRecoveryCodes_MfaNotEnabled_ReturnsNull()
    {
        SetupExistingProps(1, new MfaProps { Enabled = false });
        (await _sut.RegenerateRecoveryCodesAsync(1)).Should().BeNull();
    }

    // ── ProtectState / UnprotectState ──

    [Fact]
    public void ProtectState_UnprotectState_RoundTrip()
    {
        var state = new MfaState
        {
            UserId = 42,
            Username = "alice",
            Methods = ["totp"],
            ReturnUrl = "/callback"
        };

        var token = _sut.ProtectState(state);
        token.Should().NotBeNullOrEmpty();

        var restored = _sut.UnprotectState(token);
        restored.Should().NotBeNull();
        restored!.UserId.Should().Be(42);
        restored.Username.Should().Be("alice");
    }

    [Fact]
    public void UnprotectState_Invalid_ReturnsNull()
    {
        _sut.UnprotectState("garbage").Should().BeNull();
    }

    // ── Helper: same hash logic as MfaService (SHA256, normalize) ──

    private static string HashCode(string code)
    {
        var normalized = code.Replace("-", "", StringComparison.Ordinal).ToUpperInvariant();
        var bytes = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(normalized));
        return Convert.ToHexStringLower(bytes);
    }
}
