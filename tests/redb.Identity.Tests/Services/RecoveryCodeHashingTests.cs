using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
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
/// Verifies the B4 recovery-code hashing pipeline: per-user salt + pepper + PBKDF2-SHA256,
/// constant-time comparison, and seamless legacy SHA-256 migration.
/// </summary>
public class RecoveryCodeHashingTests
{
    private readonly IRedbService _redb = Substitute.For<IRedbService>();
    private readonly MfaService _sut;

    public RecoveryCodeHashingTests()
    {
        var options = Options.Create(new RedbIdentityOptions
        {
            // Smaller iteration count for fast tests; production default is 600 000.
            RecoveryCodePbkdf2Iterations = 1_000
        });
        var pepper = RecoveryCodePepperProvider.ForTesting(new byte[] {
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
        });
        _sut = new MfaService(
            _redb,
            new IMfaMethod[] { new TotpMfaMethod(new MfaSecretProtector(
                Microsoft.AspNetCore.DataProtection.DataProtectionProvider.Create("recovery-code-tests"))) },
            Array.Empty<IMfaDeliveryChannel>(),
            new MfaStateProtector(Microsoft.AspNetCore.DataProtection.DataProtectionProvider.Create("recovery-code-tests")),
            new MfaSetupTokenProtector(Microsoft.AspNetCore.DataProtection.DataProtectionProvider.Create("recovery-code-tests")),
            options,
            pepper,
            NullLogger<MfaService>.Instance);
    }

    private static string LegacyHash(string code)
    {
        var normalized = code.Replace("-", "", StringComparison.Ordinal).ToUpperInvariant();
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(normalized));
        return Convert.ToHexStringLower(bytes);
    }

    private void SetupSingleProps(long userId, MfaProps props)
    {
        var obj = new RedbObject<MfaProps>(props) { Id = 100 };
        obj.key = userId;
        MockRedbQuery.Setup(_redb, new List<RedbObject<MfaProps>> { obj });
    }

    [Fact]
    public async Task LegacyShaHash_StillVerifies_AndIsConsumed()
    {
        var plain = "ABCD-EF23";
        var props = new MfaProps
        {
            Enabled = true,
            TotpConfirmed = true,
            RecoveryCodes = new List<string> { LegacyHash(plain), "noise" }
        };
        SetupSingleProps(1, props);

        var ok = await _sut.VerifyRecoveryCodeAsync(1, plain);

        ok.Should().BeTrue();
        props.RecoveryCodes.Should().HaveCount(1);
        props.RecoveryCodes.Single().Should().Be("noise");
    }

    [Fact]
    public async Task UnrelatedCode_DoesNotMatch()
    {
        var props = new MfaProps
        {
            Enabled = true,
            TotpConfirmed = true,
            RecoveryCodes = new List<string> { LegacyHash("ABCD-EF23") }
        };
        SetupSingleProps(2, props);

        var ok = await _sut.VerifyRecoveryCodeAsync(2, "WRONG-CODE");

        ok.Should().BeFalse();
        props.RecoveryCodes.Should().HaveCount(1);
    }

    [Fact]
    public void Pepper_IsRequired_WhenAllowEphemeralKeysFalse()
    {
        var act = () => new RecoveryCodePepperProvider(
            Options.Create(new RedbIdentityOptions { AllowEphemeralKeys = false }),
            NullLogger<RecoveryCodePepperProvider>.Instance);
        act.Should().Throw<InvalidOperationException>().WithMessage("*RecoveryCodePepper*");
    }

    [Fact]
    public void Pepper_AcceptsBase64_AndExposesBytes()
    {
        var raw = new byte[20];
        RandomNumberGenerator.Fill(raw);
        var b64 = Convert.ToBase64String(raw);
        var provider = new RecoveryCodePepperProvider(
            Options.Create(new RedbIdentityOptions { RecoveryCodePepper = b64 }),
            NullLogger<RecoveryCodePepperProvider>.Instance);

        provider.IsEphemeral.Should().BeFalse();
        provider.Pepper.Should().BeEquivalentTo(raw);
    }

    [Fact]
    public void Pepper_RejectsTooShortConfiguredValue()
    {
        var b64 = Convert.ToBase64String(new byte[8]);
        var act = () => new RecoveryCodePepperProvider(
            Options.Create(new RedbIdentityOptions { RecoveryCodePepper = b64 }),
            NullLogger<RecoveryCodePepperProvider>.Instance);
        act.Should().Throw<InvalidOperationException>().WithMessage("*16 bytes*");
    }
}
