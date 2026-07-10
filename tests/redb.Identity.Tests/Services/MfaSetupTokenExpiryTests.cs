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
/// B5 DoD: setup tokens older than the configured TTL (default 10 minutes) must be rejected
/// by <see cref="MfaService.ConfirmSetupAsync"/>.
/// </summary>
public sealed class MfaSetupTokenExpiryTests
{
    [Fact]
    public async Task ConfirmSetup_WithExpiredToken_ReturnsNull()
    {
        var redb = Substitute.For<IRedbService>();
        var dpProvider = DataProtectionProvider.Create("redb-mfa-setup-expiry-tests");
        var secretProtector = new MfaSecretProtector(dpProvider);
        var stateProtector = new MfaStateProtector(dpProvider);
        var setupTokenProtector = new MfaSetupTokenProtector(dpProvider);
        var totp = new TotpMfaMethod(secretProtector);

        var sut = new MfaService(
            redb,
            new IMfaMethod[] { totp },
            Array.Empty<IMfaDeliveryChannel>(),
            stateProtector,
            setupTokenProtector,
            Microsoft.Extensions.Options.Options.Create(new redb.Identity.Core.Configuration.RedbIdentityOptions()),
            RecoveryCodePepperProvider.ForTesting(),
            NullLogger<MfaService>.Instance);

        // Mint an expired token directly via the protector (IssuedAt 11 minutes ago > 10-min TTL).
        var base32 = "JBSWY3DPEHPK3PXP";
        var expiredToken = setupTokenProtector.Protect(new MfaSetupTokenPayload
        {
            UserId = 42,
            MethodId = "totp",
            EncryptedSecret = secretProtector.Protect(base32),
            IssuedAt = DateTimeOffset.UtcNow.AddMinutes(-11),
            Jti = Guid.NewGuid()
        });

        MockRedbQuery.Setup(redb, new List<RedbObject<MfaProps>>());

        var code = GenerateCode(base32);
        var result = await sut.ConfirmSetupAsync(42, "totp", code, expiredToken);

        result.Should().BeNull("expired setup tokens must be rejected");
        await redb.DidNotReceive().SaveAsync(Arg.Any<RedbObject<MfaProps>>());
    }

    [Fact]
    public async Task ConfirmSetup_WithMalformedToken_ReturnsNull()
    {
        var redb = Substitute.For<IRedbService>();
        var dpProvider = DataProtectionProvider.Create("redb-mfa-setup-expiry-tests");
        var secretProtector = new MfaSecretProtector(dpProvider);
        var stateProtector = new MfaStateProtector(dpProvider);
        var totp = new TotpMfaMethod(secretProtector);

        var sut = new MfaService(
            redb,
            new IMfaMethod[] { totp },
            Array.Empty<IMfaDeliveryChannel>(),
            stateProtector,
            new MfaSetupTokenProtector(dpProvider),
            Microsoft.Extensions.Options.Options.Create(new redb.Identity.Core.Configuration.RedbIdentityOptions()),
            RecoveryCodePepperProvider.ForTesting(),
            NullLogger<MfaService>.Instance);

        MockRedbQuery.Setup(redb, new List<RedbObject<MfaProps>>());

        var result = await sut.ConfirmSetupAsync(42, "totp", "123456", "not-a-valid-token");

        result.Should().BeNull();
        await redb.DidNotReceive().SaveAsync(Arg.Any<RedbObject<MfaProps>>());
    }

    private static string GenerateCode(string base32Secret)
    {
        var key = Base32Encoding.ToBytes(base32Secret);
        var totp = new Totp(key, step: 30, totpSize: 6);
        return totp.ComputeTotp();
    }
}
