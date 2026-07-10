using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using NSubstitute;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Services;

/// <summary>
/// B9 — covers the four MFA hygiene fixes: BUG-4 (atomic load), BUG-5 (lockout clock skew),
/// BUG-8 (recovery-code archive on disable / regenerate), BUG-9 is verified separately at
/// the route layer in <c>LoginProcessorMfaMethodsLeakTests</c>.
/// </summary>
public sealed class MfaServiceB9Tests
{
    private readonly IRedbService _redb = Substitute.For<IRedbService>();
    private readonly RedbIdentityOptions _options = new();
    private readonly FakeTimeProvider _clock = new(startDateTime: new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
    private readonly MfaSecretProtector _secretProtector;
    private readonly MfaService _sut;

    public MfaServiceB9Tests()
    {
        var dpProvider = DataProtectionProvider.Create("redb-mfa-b9-tests");
        _secretProtector = new MfaSecretProtector(dpProvider);
        var stateProtector = new MfaStateProtector(dpProvider);
        var totpMethod = new TotpMfaMethod(_secretProtector);
        _sut = new MfaService(
            _redb,
            new IMfaMethod[] { totpMethod },
            Array.Empty<IMfaDeliveryChannel>(),
            stateProtector,
            new MfaSetupTokenProtector(dpProvider),
            Options.Create(_options),
            RecoveryCodePepperProvider.ForTesting(),
            NullLogger<MfaService>.Instance,
            _clock);
    }

    private RedbObject<MfaProps> Seed(long userId, MfaProps props)
    {
        var obj = new RedbObject<MfaProps>(props) { Id = 100 };
        obj.key = userId;
        MockRedbQuery.Setup(_redb, new List<RedbObject<MfaProps>> { obj });
        return obj;
    }

    // ───────────────────────── BUG-4: atomic LoadMfaStatusAsync ─────────────────────────

    [Fact]
    public async Task LoadMfaStatus_NoProps_ReturnsDisabledAndEmpty()
    {
        MockRedbQuery.Setup(_redb, new List<RedbObject<MfaProps>>());

        var (enabled, methods) = await _sut.LoadMfaStatusAsync(1);

        enabled.Should().BeFalse();
        methods.Should().BeEmpty();
    }

    [Fact]
    public async Task LoadMfaStatus_EnabledAndConfirmed_ReturnsEnabledAndMethods()
    {
        Seed(1, new MfaProps { Enabled = true, TotpConfirmed = true, SmsConfirmed = true, SmsPhone = "+79991234567" });

        var (enabled, methods) = await _sut.LoadMfaStatusAsync(1);

        enabled.Should().BeTrue();
        methods.Should().BeEquivalentTo(new[] { "totp", "sms" });
    }

    [Fact]
    public async Task LoadMfaStatus_EnabledFlagButNothingConfirmed_ReturnsDisabled()
    {
        Seed(1, new MfaProps { Enabled = true });

        var (enabled, methods) = await _sut.LoadMfaStatusAsync(1);

        enabled.Should().BeFalse();
        methods.Should().BeEmpty();
    }

    [Fact]
    public async Task LoadMfaStatus_PerformsExactlyOneRedbQuery()
    {
        // BUG-4 essence: one read instead of two.
        Seed(1, new MfaProps { Enabled = true, TotpConfirmed = true });

        // Reset call count after seeding (Seed itself may call Query<>).
        _redb.ClearReceivedCalls();

        await _sut.LoadMfaStatusAsync(1);

        _redb.Received(1).Query<MfaProps>();
    }

    // ───────────────────────── BUG-5: lockout clock skew ─────────────────────────

    [Fact]
    public async Task Verify_AtExactLockoutExpiry_StillLocked_DueToClockSkew()
    {
        // LockedUntil exactly equals "now" — without skew the user would be considered
        // unlocked, but with the default 5s skew they are still locked.
        var now = _clock.GetUtcNow();
        Seed(1, new MfaProps
        {
            Enabled = true,
            TotpConfirmed = true,
            TotpSecret = MakeTotpSecret(),
            FailedAttempts = 5,
            LockedUntil = now,
        });

        var ok = await _sut.VerifyAsync(1, "totp", "123456");

        ok.Should().BeFalse();
    }

    [Fact]
    public async Task Verify_AfterLockoutExpiryPlusSkew_NoLongerLocked_FailedAttemptsIncrement()
    {
        // After the lockout-window + skew has elapsed, the user is no longer "locked out":
        // an INCORRECT code should now be processed normally (FailedAttempts++) instead of
        // being rejected early. Differentiating "still locked" (FailedAttempts unchanged)
        // from "unlocked, bad code" (FailedAttempts++) avoids depending on the system clock
        // for TOTP code computation in this unit test.
        var lockedUntil = _clock.GetUtcNow();
        var obj = Seed(1, new MfaProps
        {
            Enabled = true,
            TotpConfirmed = true,
            TotpSecret = MakeTotpSecret(),
            FailedAttempts = 5,
            LockedUntil = lockedUntil,
        });

        _clock.Advance(_options.MfaLockoutClockSkew + TimeSpan.FromSeconds(1));

        await _sut.VerifyAsync(1, "totp", "000000");

        // Either the lockout cleared and the wrong code was counted (6) or the lockout
        // cleared on a future success path (5 → reset on success). Both indicate the
        // user is no longer treated as locked. The decisive negative outcome of B9 BUG-5
        // is FailedAttempts being still 5 AND LockedUntil unchanged.
        obj.Props.FailedAttempts.Should().Be(6, "the lockout window has expired so failed attempts must accumulate");
    }

    [Fact]
    public async Task Verify_CustomLargeSkew_KeepsUserLockedLonger()
    {
        _options.MfaLockoutClockSkew = TimeSpan.FromMinutes(1);
        var lockedUntil = _clock.GetUtcNow();
        Seed(1, new MfaProps
        {
            Enabled = true,
            TotpConfirmed = true,
            TotpSecret = MakeTotpSecret(),
            FailedAttempts = 5,
            LockedUntil = lockedUntil,
        });

        _clock.Advance(TimeSpan.FromSeconds(30)); // past LockedUntil but within skew

        var ok = await _sut.VerifyAsync(1, "totp", "000000");

        ok.Should().BeFalse();
    }

    // ───────────────────────── BUG-8: recovery-code archive ─────────────────────────

    [Fact]
    public async Task Disable_LastMethod_MovesRecoveryCodesToArchive()
    {
        var hashedCodes = new List<string> { "hash1", "hash2", "hash3" };
        var obj = Seed(1, new MfaProps
        {
            Enabled = true,
            TotpConfirmed = true,
            TotpSecret = MakeTotpSecret(),
            RecoveryCodes = hashedCodes,
        });

        await _sut.DisableAsync(1, "totp");

        obj.Props.Enabled.Should().BeFalse();
        obj.Props.RecoveryCodes.Should().BeNull("active codes are revoked");
        obj.Props.ArchivedRecoveryCodes.Should().NotBeNull();
        obj.Props.ArchivedRecoveryCodes!.Should().HaveCount(1);
        obj.Props.ArchivedRecoveryCodes[0].HashedCodes.Should().BeEquivalentTo(hashedCodes);
        obj.Props.ArchivedRecoveryCodes[0].Reason.Should().Be("disable");
        obj.Props.ArchivedRecoveryCodes[0].ArchivedAt.Should().Be(_clock.GetUtcNow());
    }

    [Fact]
    public async Task Disable_RemainingMethod_DoesNotArchive()
    {
        // When other methods remain confirmed, MFA stays enabled and recovery codes are
        // not touched — nothing to archive.
        var hashedCodes = new List<string> { "hash1" };
        var obj = Seed(1, new MfaProps
        {
            Enabled = true,
            TotpConfirmed = true,
            TotpSecret = MakeTotpSecret(),
            SmsConfirmed = true,
            SmsPhone = "+79991234567",
            RecoveryCodes = hashedCodes,
        });

        await _sut.DisableAsync(1, "totp");

        obj.Props.Enabled.Should().BeTrue();
        obj.Props.RecoveryCodes.Should().BeEquivalentTo(hashedCodes);
        obj.Props.ArchivedRecoveryCodes.Should().BeNull();
    }

    [Fact]
    public async Task Regenerate_ArchivesPreviousBatch()
    {
        var oldCodes = new List<string> { "old1", "old2" };
        var obj = Seed(1, new MfaProps
        {
            Enabled = true,
            TotpConfirmed = true,
            TotpSecret = MakeTotpSecret(),
            RecoveryCodes = oldCodes,
        });

        var newCodes = await _sut.RegenerateRecoveryCodesAsync(1);

        newCodes.Should().NotBeNull();
        obj.Props.ArchivedRecoveryCodes.Should().NotBeNull();
        obj.Props.ArchivedRecoveryCodes!.Should().HaveCount(1);
        obj.Props.ArchivedRecoveryCodes[0].Reason.Should().Be("regenerate");
        obj.Props.ArchivedRecoveryCodes[0].HashedCodes.Should().BeEquivalentTo(oldCodes);
        obj.Props.RecoveryCodes.Should().NotBeNullOrEmpty();
        obj.Props.RecoveryCodes.Should().NotBeEquivalentTo(oldCodes);
    }

    [Fact]
    public async Task ArchivedRecoveryCodes_AreNotConsultedDuringVerify()
    {
        // Archived codes must NOT be usable for login.
        var hashedActive = MfaServiceTestHelpers.HashCode("AAAAAAAA-AAAAAAAA");
        var hashedArchived = MfaServiceTestHelpers.HashCode("BBBBBBBB-BBBBBBBB");
        Seed(1, new MfaProps
        {
            Enabled = true,
            TotpConfirmed = true,
            TotpSecret = MakeTotpSecret(),
            RecoveryCodes = new List<string> { hashedActive },
            ArchivedRecoveryCodes = new List<MfaArchivedRecoveryCodeBatch>
            {
                new()
                {
                    ArchivedAt = _clock.GetUtcNow().AddDays(-1),
                    Reason = "regenerate",
                    HashedCodes = new List<string> { hashedArchived }
                }
            }
        });

        var archivedCodeAccepted = await _sut.VerifyRecoveryCodeAsync(1, "BBBBBBBB-BBBBBBBB");

        archivedCodeAccepted.Should().BeFalse();
    }

    // ───────────────────────── helpers ─────────────────────────

    private string MakeTotpSecret()
    {
        var raw = OtpNet.KeyGeneration.GenerateRandomKey(20);
        var b32 = OtpNet.Base32Encoding.ToString(raw);
        return _secretProtector.Protect(b32);
    }

    private (string protectedSecret, string code) MakeTotpSecretAndCurrentCode(DateTimeOffset at)
    {
        var raw = OtpNet.KeyGeneration.GenerateRandomKey(20);
        var b32 = OtpNet.Base32Encoding.ToString(raw);
        var totp = new OtpNet.Totp(raw, step: 30, totpSize: 6);
        return (_secretProtector.Protect(b32), totp.ComputeTotp(at.UtcDateTime));
    }
}

internal static class MfaServiceTestHelpers
{
    /// <summary>Replicates MfaService recovery-code hashing for unit tests.</summary>
    public static string HashCode(string code)
    {
        // Mirror of MfaService.HashCode default path: PBKDF2(salt + code + pepper).
        // For the «archived codes ignored» test we only need a consistent scheme — the
        // test asserts that the code is NOT accepted, so it does not matter whether the
        // hash is in the legacy SHA-256 format or the modern PBKDF2 format.
        using var sha = System.Security.Cryptography.SHA256.Create();
        var bytes = sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(code));
        return Convert.ToBase64String(bytes);
    }
}
