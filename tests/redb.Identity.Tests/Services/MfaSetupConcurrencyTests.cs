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
/// B5 DoD: two parallel <see cref="MfaService.SetupAsync"/> invocations must produce
/// independent, non-conflicting setup tokens. Neither call may persist anything to the
/// MFA props row, so a subsequent <see cref="MfaService.ConfirmSetupAsync"/> with either
/// token completes against an empty/clean row.
/// </summary>
public sealed class MfaSetupConcurrencyTests
{
    private readonly IRedbService _redb = Substitute.For<IRedbService>();
    private readonly MfaService _sut;

    public MfaSetupConcurrencyTests()
    {
        var dpProvider = DataProtectionProvider.Create("redb-mfa-setup-concurrency-tests");
        var secretProtector = new MfaSecretProtector(dpProvider);
        var stateProtector = new MfaStateProtector(dpProvider);
        var totp = new TotpMfaMethod(secretProtector);
        _sut = new MfaService(
            _redb,
            new IMfaMethod[] { totp },
            Array.Empty<IMfaDeliveryChannel>(),
            stateProtector,
            new MfaSetupTokenProtector(dpProvider),
            Microsoft.Extensions.Options.Options.Create(new redb.Identity.Core.Configuration.RedbIdentityOptions()),
            RecoveryCodePepperProvider.ForTesting(),
            NullLogger<MfaService>.Instance);
    }

    [Fact]
    public async Task TwoParallelSetups_ProduceDistinctTokens_AndDoNotPersist()
    {
        MockRedbQuery.Setup(_redb, new List<RedbObject<MfaProps>>());

        var results = await Task.WhenAll(
            _sut.SetupAsync(42, "totp", "alice"),
            _sut.SetupAsync(42, "totp", "alice"));
        var r1 = results[0];
        var r2 = results[1];

        r1.SetupToken.Should().NotBeNullOrEmpty();
        r2.SetupToken.Should().NotBeNullOrEmpty();
        r1.SetupToken.Should().NotBe(r2.SetupToken,
            "each setup must mint an independent token (Jti and possibly secret differ)");
        r1.SecretBase32.Should().NotBe(r2.SecretBase32,
            "each setup generates a fresh TOTP secret");

        // No database writes occurred during either setup.
        await _redb.DidNotReceive().SaveAsync(Arg.Any<RedbObject<MfaProps>>());
    }

    [Fact]
    public async Task ConfirmingFirstToken_DoesNotInvalidateSecondToken()
    {
        // Setup #1
        MockRedbQuery.Setup(_redb, new List<RedbObject<MfaProps>>());
        var r1 = await _sut.SetupAsync(42, "totp", "alice");
        // Setup #2 (parallel attempt)
        MockRedbQuery.Setup(_redb, new List<RedbObject<MfaProps>>());
        var r2 = await _sut.SetupAsync(42, "totp", "alice");

        // Confirm with token #1
        MockRedbQuery.Setup(_redb, new List<RedbObject<MfaProps>>());
        var code1 = GenerateCode(r1.SecretBase32!);
        var recovery1 = await _sut.ConfirmSetupAsync(42, "totp", code1, r1.SetupToken!);
        recovery1.Should().NotBeNull("first confirm must succeed and return recovery codes");

        // Token #2 is still valid — it carries an independent secret and Jti.
        // The SUT does not maintain a server-side blacklist of consumed tokens (B5 design),
        // so confirming #2 also succeeds (and would overwrite the secret in a real DB).
        MockRedbQuery.Setup(_redb, new List<RedbObject<MfaProps>>());
        var code2 = GenerateCode(r2.SecretBase32!);
        var recovery2 = await _sut.ConfirmSetupAsync(42, "totp", code2, r2.SetupToken!);
        recovery2.Should().NotBeNull("second token remains usable until expiry");
    }

    private static string GenerateCode(string base32Secret)
    {
        var key = Base32Encoding.ToBytes(base32Secret);
        var totp = new Totp(key, step: 30, totpSize: 6);
        return totp.ComputeTotp();
    }
}
