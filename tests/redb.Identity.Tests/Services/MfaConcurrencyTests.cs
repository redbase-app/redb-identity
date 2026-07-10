using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using OtpNet;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Services;

/// <summary>
/// G2 — MFA concurrency on REAL PostgreSQL.
///
/// Validates the SELECT FOR UPDATE serialization implemented in <c>MfaVerifyProcessor</c> by
/// replicating the same per-call pattern (new IServiceScope → new IRedbService → BeginTransaction
/// → LockForUpdate(mfaObjId) → MfaService method → Commit) under fan-out load against the same
/// MfaProps row.
///
/// Invariants asserted:
///   1. Recovery code double-spend: N parallel verifies of the same code → exactly 1 success,
///      RecoveryCodes count drops by exactly 1.
///   2. FailedAttempts atomicity: 5 parallel wrong codes (below the 5-attempt threshold)
///      → final FailedAttempts == 5 (no lost-update).
///   3. Lockout enforcement under contention: 10 parallel wrong codes → first 5 increment and
///      latch the lockout, remaining 5 short-circuit on IsLockedOut without incrementing
///      → final FailedAttempts == 5, LockedUntil populated.
/// </summary>
[Collection("Postgres")]
public sealed class MfaConcurrencyTests
{
    private readonly PostgresFixture _fx;
    private readonly IDataProtectionProvider _dp = DataProtectionProvider.Create("redb-mfa-concurrency-tests");
    // Pepper MUST be stable across all MfaService instances in this test, otherwise concurrent
    // recovery-code verifies see different hashes than what was persisted during bootstrap.
    private readonly RecoveryCodePepperProvider _pepper = RecoveryCodePepperProvider.ForTesting(
        new byte[] { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32 });

    public MfaConcurrencyTests(PostgresFixture fx)
    {
        _fx = fx;
    }

    private MfaService BuildService(IRedbService redb)
    {
        var secretProtector = new MfaSecretProtector(_dp);
        var stateProtector = new MfaStateProtector(_dp);
        var setupProtector = new MfaSetupTokenProtector(_dp);
        var totpMethod = new TotpMfaMethod(secretProtector);
        return new MfaService(
            redb,
            new IMfaMethod[] { totpMethod },
            Array.Empty<IMfaDeliveryChannel>(),
            stateProtector,
            setupProtector,
            Options.Create(new RedbIdentityOptions()),
            _pepper,
            NullLogger<MfaService>.Instance);
    }

    /// <summary>
    /// Bootstraps a confirmed-MFA row for a fresh user and returns (userId, recoveryCodes, mfaObjectId).
    /// Uses a unique userId to avoid cross-test contention on the same row.
    /// </summary>
    private async Task<(long userId, string[]? recoveryCodes, long mfaObjectId)> BootstrapUserAsync()
    {
        var userId = DateTimeOffset.UtcNow.UtcTicks + Random.Shared.Next(1, 10_000);
        var svc = BuildService(_fx.Redb);
        var setup = await svc.SetupAsync(userId, "totp", $"u{userId}");
        var totp = new Totp(Base32Encoding.ToBytes(setup.SecretBase32!), step: 30, totpSize: 6);
        var code = totp.ComputeTotp();
        var recoveryCodes = await svc.ConfirmSetupAsync(userId, "totp", code, setup.SetupToken!);
        var mfaObjId = await svc.GetMfaObjectIdAsync(userId, default);
        mfaObjId.Should().BeGreaterThan(0);
        return (userId, recoveryCodes, mfaObjId);
    }

    private async Task<MfaProps> ReloadPropsAsync(long userId)
    {
        var obj = await _fx.Redb.Query<MfaProps>()
            .WhereRedb(o => o.Key == userId)
            .FirstOrDefaultAsync();
        obj.Should().NotBeNull();
        return obj!.Props;
    }

    /// <summary>
    /// Per-task callback executes inside a freshly-created scope with its own IRedbService /
    /// transaction / FOR UPDATE lock — mirroring <see cref="redb.Identity.Core.Routes.Processors.MfaVerifyProcessor"/>.
    /// </summary>
    private async Task<T> RunIsolatedAsync<T>(long mfaObjId, Func<MfaService, IRedbService, Task<T>> body)
    {
        await using var scope = _fx.Services.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var svc = BuildService(redb);

        await using var tx = await redb.Context.BeginTransactionAsync();
        await redb.LockForUpdateAsync(mfaObjId);
        var result = await body(svc, redb);
        await tx.CommitAsync();
        return result;
    }

    [Fact]
    public async Task RecoveryCode_DoubleSpend_OnlyOneSucceeds()
    {
        var (userId, recoveryCodes, mfaObjId) = await BootstrapUserAsync();
        var sharedCode = recoveryCodes![0];
        const int parallelism = 50;

        var tasks = Enumerable.Range(0, parallelism)
            .Select(_ => RunIsolatedAsync(mfaObjId, (svc, _) => svc.VerifyRecoveryCodeAsync(userId, sharedCode)))
            .ToArray();
        var results = await Task.WhenAll(tasks);

        results.Count(r => r).Should().Be(1, "exactly one of the racing verifies must consume the code");
        var props = await ReloadPropsAsync(userId);
        props.RecoveryCodes!.Count.Should().Be(recoveryCodes!.Length - 1);
        // The remaining `parallelism - 1` losers each counted as a wrong attempt → lockout latches at 5.
        props.LockedUntil.Should().NotBeNull("the losing attempts must be counted as failures and trigger lockout");
    }

    [Fact]
    public async Task FailedAttempts_FiveParallelWrongCodes_FinalCountIsFive()
    {
        var (userId, _, mfaObjId) = await BootstrapUserAsync();
        const int parallelism = 5; // exactly the lockout threshold

        var tasks = Enumerable.Range(0, parallelism)
            .Select(_ => RunIsolatedAsync(mfaObjId, (svc, _) => svc.VerifyAsync(userId, "totp", "000000")))
            .ToArray();
        var results = await Task.WhenAll(tasks);

        results.Should().AllSatisfy(r => r.Should().BeFalse());
        var props = await ReloadPropsAsync(userId);
        props.FailedAttempts.Should().Be(parallelism, "FOR UPDATE serialization must prevent lost-update on FailedAttempts");
        props.LockedUntil.Should().NotBeNull("the 5th increment hits the lockout threshold");
    }

    [Fact]
    public async Task Lockout_TenParallelWrongCodes_LatchesAfterThreshold()
    {
        var (userId, _, mfaObjId) = await BootstrapUserAsync();
        const int parallelism = 10; // double the threshold

        var tasks = Enumerable.Range(0, parallelism)
            .Select(_ => RunIsolatedAsync(mfaObjId, (svc, _) => svc.VerifyAsync(userId, "totp", "000000")))
            .ToArray();
        var results = await Task.WhenAll(tasks);

        results.Should().AllSatisfy(r => r.Should().BeFalse());
        var props = await ReloadPropsAsync(userId);
        // Only the first 5 serialized attempts increment; the rest short-circuit on IsLockedOut.
        props.FailedAttempts.Should().Be(5, "attempts after lockout must not increment FailedAttempts");
        props.LockedUntil.Should().NotBeNull();
    }
}
