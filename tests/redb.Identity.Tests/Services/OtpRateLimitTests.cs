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
/// B6 DoD: sliding-window OTP rate limit. Verifies that exhausting the per-hour quota
/// is bounded by a true rolling window, not a calendar-hour bucket — i.e. an attacker
/// who burst-sends N OTPs cannot regain quota by waiting for the next "hour" tick;
/// they must wait for the oldest in-window timestamp to age out.
/// </summary>
public sealed class OtpRateLimitTests
{
    private readonly IRedbService _redb = Substitute.For<IRedbService>();
    private readonly RedbIdentityOptions _options;
    private readonly FakeTimeProvider _clock;
    private readonly FakeDeliveryChannel _smsChannel = new("sms");
    private readonly MfaService _sut;

    public OtpRateLimitTests()
    {
        // Set OtpCooldown to 0 so the test can drive purely through the sliding window.
        _options = new RedbIdentityOptions
        {
            OtpCooldown = TimeSpan.Zero,
            OtpMaxPerHour = 5
        };

        _clock = new FakeTimeProvider(startDateTime: new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));

        var dpProvider = DataProtectionProvider.Create("redb-mfa-otp-ratelimit-tests");
        var secretProtector = new MfaSecretProtector(dpProvider);
        var stateProtector = new MfaStateProtector(dpProvider);
        var setupTokenProtector = new MfaSetupTokenProtector(dpProvider);

        _sut = new MfaService(
            _redb,
            new IMfaMethod[] { new TotpMfaMethod(secretProtector), new SmsMfaMethod(), new EmailMfaMethod() },
            new IMfaDeliveryChannel[] { _smsChannel },
            stateProtector,
            setupTokenProtector,
            Options.Create(_options),
            RecoveryCodePepperProvider.ForTesting(),
            NullLogger<MfaService>.Instance,
            _clock);
    }

    private void Setup(MfaProps props)
    {
        var obj = new RedbObject<MfaProps>(props) { Id = 100 };
        obj.key = 1;
        MockRedbQuery.Setup(_redb, new List<RedbObject<MfaProps>> { obj });
    }

    private MfaProps NewSmsProps() => new()
    {
        Enabled = true,
        SmsPhone = "+79991234567",
        SmsConfirmed = true
    };

    [Fact]
    public async Task SendingNPlusOneInOneMinute_GetsRateLimited()
    {
        // Goal: 5 successful sends, 6th rejected. All within ~1 minute, so a calendar-hour
        // bucket would never reset and the cap would still hit. The point of this test is
        // baseline behaviour parity; the next test proves the new logic differs from a bucket.
        var props = NewSmsProps();
        Setup(props);

        for (var i = 0; i < _options.OtpMaxPerHour; i++)
        {
            _clock.Advance(TimeSpan.FromSeconds(10));
            var ok = await _sut.CreateChallengeAsync(1, "alice", "sms", returnUrl: null);
            ok.Success.Should().BeTrue($"send #{i + 1} should be permitted");
        }

        _clock.Advance(TimeSpan.FromSeconds(10));
        var rejected = await _sut.CreateChallengeAsync(1, "alice", "sms", returnUrl: null);

        rejected.Success.Should().BeFalse();
        rejected.Error.Should().Be("rate_limited");
        rejected.RetryAfterSeconds.Should().NotBeNull();
        rejected.RetryAfterSeconds!.Value.Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task BurstAtHourBoundary_DoesNotResetQuota()
    {
        // Regression test for the exact bug B6 fixes. With the old "current calendar hour"
        // bucket, an attacker could fill quota in the last seconds of one hour, then burst
        // OtpMaxPerHour more OTPs in the first second of the next hour. The sliding window
        // must refuse the burst because the prior sends are still inside the rolling 60-min
        // window.
        var props = NewSmsProps();
        Setup(props);

        // Fill the quota across the last ~30s of a calendar hour.
        // Start the clock at HH:59:30 to provoke the boundary.
        _clock.SetUtcNow(new DateTimeOffset(2026, 1, 1, 12, 59, 30, TimeSpan.Zero));
        for (var i = 0; i < _options.OtpMaxPerHour; i++)
        {
            _clock.Advance(TimeSpan.FromSeconds(5));
            var ok = await _sut.CreateChallengeAsync(1, "alice", "sms", returnUrl: null);
            ok.Success.Should().BeTrue($"setup send #{i + 1} should succeed");
        }

        // Cross the calendar-hour boundary (now at ~13:00:00) and immediately try again.
        _clock.Advance(TimeSpan.FromSeconds(5));
        var crossBoundary = await _sut.CreateChallengeAsync(1, "alice", "sms", returnUrl: null);

        crossBoundary.Success.Should().BeFalse(
            "sliding window must keep the previous hour's quota in scope across calendar boundary");
        crossBoundary.Error.Should().Be("rate_limited");
    }

    [Fact]
    public async Task QuotaReleases_AfterOldestEntryAgesOut()
    {
        // After waiting OtpRateLimitWindow past the oldest in-window send, that send drops
        // out and one new send is permitted again.
        var props = NewSmsProps();
        Setup(props);

        for (var i = 0; i < _options.OtpMaxPerHour; i++)
        {
            _clock.Advance(TimeSpan.FromSeconds(10));
            (await _sut.CreateChallengeAsync(1, "alice", "sms", returnUrl: null)).Success.Should().BeTrue();
        }

        // Quota now full. Advance past the oldest entry's 1h expiry (oldest was at +10s
        // from start). Add a small slack to be safely past the cutoff.
        _clock.Advance(TimeSpan.FromHours(1));

        var afterAgeOut = await _sut.CreateChallengeAsync(1, "alice", "sms", returnUrl: null);

        afterAgeOut.Success.Should().BeTrue("oldest timestamp aged out of the sliding window");
    }

    [Fact]
    public async Task RecentTimestamps_AreCappedToBoundedSize()
    {
        // Drive many sends across a long span (cooldown=0, OtpMaxPerHour=very high) so that
        // the cap kicks in. The list must not grow unbounded.
        _options.OtpMaxPerHour = 1000; // disable hourly throttle for this test
        var props = NewSmsProps();
        Setup(props);

        for (var i = 0; i < 80; i++) // > 50 cap
        {
            // Spread sends over ~80 minutes so most stay in the 1h window.
            _clock.Advance(TimeSpan.FromMinutes(1));
            (await _sut.CreateChallengeAsync(1, "alice", "sms", returnUrl: null)).Success.Should().BeTrue();
        }

        props.RecentOtpTimestamps.Should().NotBeNull();
        // Cap is 50 (RecentOtpTimestampsCap). Pruning by 1h window will also drop entries
        // older than the cutoff, so the actual count may be <= 50.
        props.RecentOtpTimestamps!.Count.Should().BeLessThanOrEqualTo(50);
    }

    /// <summary>Local fake delivery channel — same shape as the one in MfaServiceChallengeTests.</summary>
    private sealed class FakeDeliveryChannel : IMfaDeliveryChannel
    {
        public string ChannelId { get; }
        public string DisplayName => ChannelId.ToUpperInvariant();

        public FakeDeliveryChannel(string channelId) => ChannelId = channelId;

        public Task SendCodeAsync(string destination, string code, CancellationToken ct = default)
            => Task.CompletedTask;
    }
}
