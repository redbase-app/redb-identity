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
/// B7 DoD: <see cref="MfaService.ConfirmSetupAsync"/> must reject any confirm whose body
/// <c>userId</c> (or <c>methodId</c>) does not match the encrypted setup-token payload —
/// defends against an attacker who possesses a valid token for one user and tries to apply
/// it against another user's account. Implemented as part of B5 token binding; this test
/// pins the behaviour and the indistinguishable failure response.
/// </summary>
public sealed class MfaSetupConfirmBindingTests
{
    private static MfaService BuildSut(IRedbService redb, out MfaSetupTokenProtector setupTokenProtector, out MfaSecretProtector secretProtector)
    {
        var dpProvider = DataProtectionProvider.Create("redb-mfa-setup-binding-tests");
        secretProtector = new MfaSecretProtector(dpProvider);
        var stateProtector = new MfaStateProtector(dpProvider);
        setupTokenProtector = new MfaSetupTokenProtector(dpProvider);
        var totp = new TotpMfaMethod(secretProtector);

        return new MfaService(
            redb,
            new IMfaMethod[] { totp, new SmsMfaMethod(), new EmailMfaMethod() },
            Array.Empty<IMfaDeliveryChannel>(),
            stateProtector,
            setupTokenProtector,
            Microsoft.Extensions.Options.Options.Create(new redb.Identity.Core.Configuration.RedbIdentityOptions()),
            RecoveryCodePepperProvider.ForTesting(),
            NullLogger<MfaService>.Instance);
    }

    [Fact]
    public async Task ConfirmSetup_WithMismatchedBodyUserId_ReturnsNull_NoSave()
    {
        var redb = Substitute.For<IRedbService>();
        var sut = BuildSut(redb, out var setupTokenProtector, out var secretProtector);
        MockRedbQuery.Setup(redb, new List<RedbObject<MfaProps>>());

        const string base32 = "JBSWY3DPEHPK3PXP";

        // Token issued for user 42 (the legitimate setup initiator).
        var token = setupTokenProtector.Protect(new MfaSetupTokenPayload
        {
            UserId = 42,
            MethodId = "totp",
            EncryptedSecret = secretProtector.Protect(base32),
            Jti = Guid.NewGuid()
        });

        var validCode = GenerateCode(base32);

        // Attacker submits the token but with userId=99 in the body, hoping to bind MFA to
        // their own account using the victim's (or their own) token+secret pair.
        var result = await sut.ConfirmSetupAsync(99, "totp", validCode, token);

        result.Should().BeNull("token UserId binding must reject body userId mismatch");
        await redb.DidNotReceive().SaveAsync(Arg.Any<RedbObject<MfaProps>>());
    }

    [Fact]
    public async Task ConfirmSetup_WithMismatchedMethod_ReturnsNull_NoSave()
    {
        var redb = Substitute.For<IRedbService>();
        var sut = BuildSut(redb, out var setupTokenProtector, out var secretProtector);
        MockRedbQuery.Setup(redb, new List<RedbObject<MfaProps>>());

        const string base32 = "JBSWY3DPEHPK3PXP";

        var token = setupTokenProtector.Protect(new MfaSetupTokenPayload
        {
            UserId = 42,
            MethodId = "totp",
            EncryptedSecret = secretProtector.Protect(base32),
            Jti = Guid.NewGuid()
        });

        // Caller sends the same token but claims it's for "sms" — this would otherwise let
        // an attacker route a TOTP-issued token through a different method's confirm path.
        var result = await sut.ConfirmSetupAsync(42, "sms", "123456", token);

        result.Should().BeNull("methodId binding must reject token/method mismatch");
        await redb.DidNotReceive().SaveAsync(Arg.Any<RedbObject<MfaProps>>());
    }

    [Fact]
    public async Task ConfirmSetup_MismatchAndExpiry_ReturnSameNullResponse_NoLeakage()
    {
        // Both classes of failure (token/userId mismatch AND expired/malformed token) must
        // be indistinguishable to the caller — same null return, no exception, no save.
        // Pins the B7 DoD requirement of "the same message for all failure classes".
        var redb = Substitute.For<IRedbService>();
        var sut = BuildSut(redb, out var setupTokenProtector, out var secretProtector);
        MockRedbQuery.Setup(redb, new List<RedbObject<MfaProps>>());

        const string base32 = "JBSWY3DPEHPK3PXP";

        var goodToken = setupTokenProtector.Protect(new MfaSetupTokenPayload
        {
            UserId = 42,
            MethodId = "totp",
            EncryptedSecret = secretProtector.Protect(base32),
            Jti = Guid.NewGuid()
        });
        var expiredToken = setupTokenProtector.Protect(new MfaSetupTokenPayload
        {
            UserId = 42,
            MethodId = "totp",
            EncryptedSecret = secretProtector.Protect(base32),
            IssuedAt = DateTimeOffset.UtcNow.AddMinutes(-11),
            Jti = Guid.NewGuid()
        });

        var validCode = GenerateCode(base32);

        var mismatchResult = await sut.ConfirmSetupAsync(99, "totp", validCode, goodToken);
        var expiryResult = await sut.ConfirmSetupAsync(42, "totp", validCode, expiredToken);
        var malformedResult = await sut.ConfirmSetupAsync(42, "totp", validCode, "not-a-token");

        mismatchResult.Should().BeNull();
        expiryResult.Should().BeNull();
        malformedResult.Should().BeNull();
        await redb.DidNotReceive().SaveAsync(Arg.Any<RedbObject<MfaProps>>());
    }

    [Fact]
    public async Task ConfirmSetup_WithUnknownMethod_ReturnsNull_NoSave()
    {
        // B7 hardening: an unknown methodId must NOT raise (distinguishable from null) —
        // it must collapse into the same null response as any other failure.
        var redb = Substitute.For<IRedbService>();
        var sut = BuildSut(redb, out _, out _);
        MockRedbQuery.Setup(redb, new List<RedbObject<MfaProps>>());

        var result = await sut.ConfirmSetupAsync(42, "no-such-method", "123456", "anything");

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
