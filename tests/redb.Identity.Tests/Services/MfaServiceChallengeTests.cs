using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Exceptions;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Services;

/// <summary>
/// Unit tests for <see cref="MfaService.CreateChallengeAsync"/>:
/// rate limiting, delivery dispatch, success path, masked destination, errors.
/// </summary>
public sealed class MfaServiceChallengeTests
{
    private readonly IRedbService _redb = Substitute.For<IRedbService>();
    private readonly MfaStateProtector _stateProtector;
    private readonly MfaSecretProtector _secretProtector;
    private readonly TotpMfaMethod _totpMethod;
    private readonly SmsMfaMethod _smsMethod = new();
    private readonly EmailMfaMethod _emailMethod = new();
    private readonly FakeDeliveryChannel _smsChannel = new("sms");
    private readonly FakeDeliveryChannel _emailChannel = new("email");
    private readonly RedbIdentityOptions _options = new();
    private readonly MfaService _sut;

    public MfaServiceChallengeTests()
    {
        var dpProvider = DataProtectionProvider.Create("redb-mfa-challenge-tests");
        _secretProtector = new MfaSecretProtector(dpProvider);
        _stateProtector = new MfaStateProtector(dpProvider);
        _totpMethod = new TotpMfaMethod(_secretProtector);

        _sut = new MfaService(
            _redb,
            new IMfaMethod[] { _totpMethod, _smsMethod, _emailMethod },
            new IMfaDeliveryChannel[] { _smsChannel, _emailChannel },
            _stateProtector,
            new MfaSetupTokenProtector(dpProvider),
            Options.Create(_options),
            RecoveryCodePepperProvider.ForTesting(),
            NullLogger<MfaService>.Instance);
    }

    private RedbObject<MfaProps> SetupExistingProps(long userId, MfaProps props)
    {
        var obj = new RedbObject<MfaProps>(props) { Id = 100 };
        obj.key = userId;
        MockRedbQuery.Setup(_redb, new List<RedbObject<MfaProps>> { obj });
        return obj;
    }

    [Fact]
    public async Task CreateChallenge_SmsConfigured_SendsCodeAndReturnsState()
    {
        SetupExistingProps(1, new MfaProps
        {
            Enabled = true,
            SmsPhone = "+79991234567",
            SmsConfirmed = true
        });

        var result = await _sut.CreateChallengeAsync(1, "alice", "sms", returnUrl: null);

        result.Success.Should().BeTrue();
        result.Method.Should().Be("sms");
        result.MaskedDestination.Should().Be("+7***4567");
        result.MfaState.Should().NotBeNullOrEmpty();
        _smsChannel.SentTo.Should().Be("+79991234567");
        _smsChannel.LastCode.Should().HaveLength(6);

        // The returned state should round-trip and carry a server-side OTP jti (B3);
        // the plaintext code no longer lives in the state blob.
        var decoded = _sut.UnprotectState(result.MfaState!);
        decoded.Should().NotBeNull();
        decoded!.OtpJti.Should().NotBeNull();
        decoded.OtpMethod.Should().Be("sms");
        decoded.UserId.Should().Be(1);
    }

    [Fact]
    public async Task CreateChallenge_EmailConfigured_SendsCodeViaEmailChannel()
    {
        SetupExistingProps(2, new MfaProps
        {
            Enabled = true,
            OtpEmail = "alice@example.com",
            EmailConfirmed = true
        });

        var result = await _sut.CreateChallengeAsync(2, "alice", "email", returnUrl: null);

        result.Success.Should().BeTrue();
        result.MaskedDestination.Should().Be("a***@example.com");
        _emailChannel.SentTo.Should().Be("alice@example.com");
        _smsChannel.SentTo.Should().BeNull(); // SMS channel not invoked
    }

    [Fact]
    public async Task CreateChallenge_UnknownMethod_FailsWithMethodNotChallengeable()
    {
        SetupExistingProps(1, new MfaProps { Enabled = true });
        var result = await _sut.CreateChallengeAsync(1, "alice", "totp", returnUrl: null);

        result.Success.Should().BeFalse();
        result.Error.Should().Be("method_not_challengeable");
    }

    [Fact]
    public async Task CreateChallenge_MfaNotEnabled_Fails()
    {
        MockRedbQuery.Setup(_redb, new List<RedbObject<MfaProps>>()); // no props
        var result = await _sut.CreateChallengeAsync(1, "alice", "sms", returnUrl: null);

        result.Success.Should().BeFalse();
        result.Error.Should().Be("mfa_not_enabled");
    }

    [Fact]
    public async Task CreateChallenge_MethodNotConfigured_Fails()
    {
        SetupExistingProps(1, new MfaProps { Enabled = true, TotpConfirmed = true });
        var result = await _sut.CreateChallengeAsync(1, "alice", "sms", returnUrl: null);

        result.Success.Should().BeFalse();
        result.Error.Should().Be("method_not_configured");
    }

    [Fact]
    public async Task CreateChallenge_NoChannelRegistered_Fails()
    {
        // Build a new SUT without channels
        var sut = new MfaService(
            _redb,
            new IMfaMethod[] { _smsMethod },
            Array.Empty<IMfaDeliveryChannel>(),
            _stateProtector,
            new MfaSetupTokenProtector(DataProtectionProvider.Create("redb-mfa-challenge-tests")),
            Options.Create(_options),
            RecoveryCodePepperProvider.ForTesting(),
            NullLogger<MfaService>.Instance);

        SetupExistingProps(1, new MfaProps
        {
            Enabled = true,
            SmsPhone = "+79991234567",
            SmsConfirmed = true
        });

        var result = await sut.CreateChallengeAsync(1, "alice", "sms", returnUrl: null);

        result.Success.Should().BeFalse();
        result.Error.Should().Be("no_channel");
    }

    [Fact]
    public async Task CreateChallenge_RateLimitedByCooldown_Fails()
    {
        SetupExistingProps(1, new MfaProps
        {
            Enabled = true,
            SmsPhone = "+79991234567",
            SmsConfirmed = true,
            LastOtpSentAt = DateTimeOffset.UtcNow // just now → within 60s cooldown
        });

        var result = await _sut.CreateChallengeAsync(1, "alice", "sms", returnUrl: null);

        result.Success.Should().BeFalse();
        result.Error.Should().Be("rate_limited");
        result.RetryAfterSeconds.Should().NotBeNull();
        result.RetryAfterSeconds!.Value.Should().BeGreaterThan(0);
        _smsChannel.SentTo.Should().BeNull(); // delivery NOT invoked when rate-limited
    }

    [Fact]
    public async Task CreateChallenge_HourlyQuotaExceeded_Fails()
    {
        // B6: sliding window — fill the window with OtpMaxPerHour timestamps spread across
        // the last hour. The next attempt must be rate-limited regardless of where the
        // calendar hour boundary falls.
        var nowUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var timestamps = Enumerable.Range(0, _options.OtpMaxPerHour)
            .Select(i => nowUnix - 60L * (i + 1)) // every minute back from now
            .ToList();

        SetupExistingProps(1, new MfaProps
        {
            Enabled = true,
            SmsPhone = "+79991234567",
            SmsConfirmed = true,
            LastOtpSentAt = DateTimeOffset.UtcNow.AddMinutes(-30), // past cooldown
            RecentOtpTimestamps = timestamps
        });

        var result = await _sut.CreateChallengeAsync(1, "alice", "sms", returnUrl: null);

        result.Success.Should().BeFalse();
        result.Error.Should().Be("rate_limited");
    }

    [Fact]
    public async Task CreateChallenge_DeliveryThrows_FailsWithDeliveryFailed()
    {
        SetupExistingProps(1, new MfaProps
        {
            Enabled = true,
            SmsPhone = "+79991234567",
            SmsConfirmed = true
        });
        _smsChannel.ThrowOnSend = new MfaDeliveryException("sms", "+79991234567", "Provider down");

        var result = await _sut.CreateChallengeAsync(1, "alice", "sms", returnUrl: null);

        result.Success.Should().BeFalse();
        result.Error.Should().Be("delivery_failed");
    }

    [Fact]
    public async Task CreateChallenge_Successful_IncrementsCounters()
    {
        var props = new MfaProps
        {
            Enabled = true,
            SmsPhone = "+79991234567",
            SmsConfirmed = true
        };
        SetupExistingProps(1, props);

        await _sut.CreateChallengeAsync(1, "alice", "sms", returnUrl: null);

        props.RecentOtpTimestamps.Should().NotBeNull();
        props.RecentOtpTimestamps!.Should().HaveCount(1);
        props.LastOtpSentAt.Should().NotBeNull();
    }

    /// <summary>Test fake for <see cref="IMfaDeliveryChannel"/>.</summary>
    private sealed class FakeDeliveryChannel : IMfaDeliveryChannel
    {
        public string ChannelId { get; }
        public string DisplayName => ChannelId.ToUpperInvariant();
        public string? SentTo { get; private set; }
        public string? LastCode { get; private set; }
        public Exception? ThrowOnSend { get; set; }

        public FakeDeliveryChannel(string channelId) => ChannelId = channelId;

        public Task SendCodeAsync(string destination, string code, CancellationToken ct = default)
        {
            if (ThrowOnSend is not null) throw ThrowOnSend;
            SentTo = destination;
            LastCode = code;
            return Task.CompletedTask;
        }
    }
}
