using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using OtpNet;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using Xunit;

namespace redb.Identity.Tests.Services;

/// <summary>
/// G3 — TOTP replay protection (RFC 6238 §5.2).
///
/// <para>
/// Verifies that <see cref="TotpMfaMethod.VerifyAsync"/> rejects any code whose time
/// step has already been accepted, and that the rejection covers BOTH the same step
/// and any earlier step still inside the verification window. The replay-guard is the
/// in-process counterpart to the SQL-level <c>SELECT FOR UPDATE</c> serialization the
/// caller (B1 / <c>MfaService.VerifyAsync</c>) performs around the read-then-write of
/// <see cref="MfaProps.LastTotpStep"/>.
/// </para>
///
/// All cases are deterministic and exercise the pure code path — no DataProtection
/// time dependency, no <see cref="System.Threading.Tasks.Task"/> scheduling — by
/// generating codes for explicit Unix timestamps via <see cref="OtpNet.Totp"/>.
/// </summary>
public sealed class TotpReplayTests
{
    private const int PeriodSeconds = 30;

    private static (TotpMfaMethod method, MfaProps props, byte[] rawSecret) Create()
    {
        var dpProvider = DataProtectionProvider.Create("redb-identity-totp-replay-tests");
        var protector = new MfaSecretProtector(dpProvider);
        var method = new TotpMfaMethod(protector);

        // 20-byte HMAC-SHA1 key per RFC 4226 §4 recommendation.
        var raw = KeyGeneration.GenerateRandomKey(20);
        var base32 = Base32Encoding.ToString(raw);
        var props = new MfaProps { TotpSecret = protector.Protect(base32) };
        return (method, props, raw);
    }

    private static string CodeForStep(byte[] secret, long step)
    {
        var totp = new Totp(secret, step: PeriodSeconds, totpSize: 6);
        var t = DateTimeOffset.FromUnixTimeSeconds(step * PeriodSeconds).UtcDateTime;
        return totp.ComputeTotp(t);
    }

    [Fact]
    public async Task VerifyAsync_SameStepReplayed_Rejected()
    {
        var (method, props, secret) = Create();
        var step = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / PeriodSeconds;
        var code = CodeForStep(secret, step);

        var first = await method.VerifyAsync(props, code);
        var second = await method.VerifyAsync(props, code);

        first.Should().BeTrue("a freshly minted code for the current step is valid");
        second.Should().BeFalse("RFC 6238 §5.2: a code from an already-accepted step must be rejected");
        props.LastTotpStep.Should().Be(step);
    }

    [Fact]
    public async Task VerifyAsync_NextStep_Accepted_ForwardProgress()
    {
        var (method, props, secret) = Create();
        var step = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / PeriodSeconds;
        // Code for the *next* step lies inside the +1 skew window, so it validates now
        // and advances LastTotpStep — mirrors the legitimate boundary case of a code
        // generated just as the time bucket flips.
        var nextCode = CodeForStep(secret, step + 1);

        var firstAccept = await method.VerifyAsync(props, nextCode);
        firstAccept.Should().BeTrue();
        props.LastTotpStep.Should().Be(step + 1);

        // Re-presenting the same forward code is now a replay against the new high-water mark.
        var replay = await method.VerifyAsync(props, nextCode);
        replay.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyAsync_OlderStepInSkewWindow_Rejected()
    {
        var (method, props, secret) = Create();
        var step = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / PeriodSeconds;
        var current = CodeForStep(secret, step);
        // Accept the current step first to set the high-water mark.
        (await method.VerifyAsync(props, current)).Should().BeTrue();

        // Code for step-1 would otherwise validate by the ±1 skew window, but the
        // replay guard must reject anything <= LastTotpStep.
        var olderCode = CodeForStep(secret, step - 1);
        var olderAccept = await method.VerifyAsync(props, olderCode);

        olderAccept.Should().BeFalse(
            "step-1 ≤ LastTotpStep — RFC 6238 §5.2 forbids accepting earlier steps even within skew");
        props.LastTotpStep.Should().Be(step, "high-water mark must not regress on rejected verifies");
    }

    [Fact]
    public async Task VerifyAsync_PreSetHighWaterMark_AnyEarlierOrEqualStep_Rejected()
    {
        var (method, props, secret) = Create();
        var step = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / PeriodSeconds;
        // Simulate a previous successful verify (e.g. process restart, durable persistence).
        props.LastTotpStep = step;

        var sameStep = await method.VerifyAsync(props, CodeForStep(secret, step));
        var earlierStep = await method.VerifyAsync(props, CodeForStep(secret, step - 1));

        sameStep.Should().BeFalse("LastTotpStep already at this step");
        earlierStep.Should().BeFalse("earlier step is below high-water mark");
        props.LastTotpStep.Should().Be(step, "rejected verifies must not mutate LastTotpStep");
    }

    [Fact]
    public async Task ConfirmAndApplyAsync_SeedsLastTotpStep_PreventsImmediateReplay()
    {
        var (method, _, _) = Create();
        var props = new MfaProps();

        var initiation = await method.InitiateSetupAsync("alice");
        var setupCode = CodeForStep(
            Base32Encoding.ToBytes(initiation.ClientResult.SecretBase32!),
            DateTimeOffset.UtcNow.ToUnixTimeSeconds() / PeriodSeconds);

        var confirmed = await method.ConfirmAndApplyAsync(props, initiation, setupCode);

        confirmed.Should().BeTrue();
        props.LastTotpStep.Should().NotBeNull(
            "B5/B7: confirm seeds LastTotpStep so the same code cannot be replayed at first verify");

        // Replaying the confirm code as the first verify must fail.
        var replay = await method.VerifyAsync(props, setupCode);
        replay.Should().BeFalse();
    }
}
