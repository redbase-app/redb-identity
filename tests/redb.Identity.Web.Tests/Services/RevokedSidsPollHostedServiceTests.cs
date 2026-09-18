using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using redb.Identity.Client.Backchannel;
using redb.Identity.Contracts.Sessions;
using redb.Identity.Contracts.Users;
using redb.Identity.Web.Configuration;
using redb.Identity.Web.Services;
using Xunit;

namespace redb.Identity.Web.Tests.Services;

/// <summary>
/// W6-0 tests for <see cref="RevokedSidsPollHostedService"/>. Exercises the
/// internal poll loop via a hand-rolled fake of <see cref="IBackchannelIdentityClient"/>
/// (no NSubstitute in this project's test dependencies).
/// </summary>
public sealed class RevokedSidsPollHostedServiceTests
{
    private sealed class FakeBackchannel : IBackchannelIdentityClient
    {
        public List<DateTimeOffset?> Calls { get; } = new();
        public Func<DateTimeOffset?, RevokedSidsSinceResponse> Responder { get; set; } =
            _ => new RevokedSidsSinceResponse
            {
                Entries = new List<RevokedSidEntry>(),
                NextCursor = DateTimeOffset.UtcNow,
            };

        public Task<RevokedSidEntry> AddRevokedSidAsync(
            string? sid, string? sub, string? clientId,
            DateTimeOffset? expiresAt = null, CancellationToken ct = default)
            => throw new NotSupportedException("AddRevokedSidAsync not used by poll service.");

        public Task<RevokedSidsSinceResponse> GetRevokedSidsSinceAsync(
            DateTimeOffset? cursor = null, CancellationToken ct = default)
        {
            Calls.Add(cursor);
            return Task.FromResult(Responder(cursor));
        }

        // N-4 / N4-6 / N4-7 surface area — not exercised by the revoked-sids poll
        // tests, but the interface requires them.
        public Task<PasswordForgotResponse> ForgotPasswordAsync(
            PasswordForgotRequest request, CancellationToken ct = default)
            => throw new NotSupportedException();

        public Task<PasswordResetResponse> ResetPasswordAsync(
            PasswordResetRequest request, CancellationToken ct = default)
            => throw new NotSupportedException();

        public Task<EmailVerifyConfirmResponse> VerifyEmailConfirmAsync(
            EmailVerifyConfirmRequest request, CancellationToken ct = default)
            => throw new NotSupportedException();

        public Task<ChangeEmailConfirmResponse> ChangeEmailConfirmAsync(
            ChangeEmailConfirmRequest request, CancellationToken ct = default)
            => throw new NotSupportedException();

        public Task<RegisterAccountResponse> RegisterAccountAsync(
            RegisterAccountRequest request, CancellationToken ct = default)
            => throw new NotSupportedException();
    }

    private static IOptions<IdentityWebOptions> Opts(TimeSpan? interval = null, bool withSecret = true)
    {
        var o = new IdentityWebOptions();
        // The poll is a cluster feature behind a service-account secret: with none configured the
        // service logs and exits before its bootstrap poll (99f2d11b). The tests of the poll itself
        // need it on; the disabled path has its own test below.
        if (withSecret) o.BackchannelClient.ClientSecret = "test-backchannel-secret";
        if (interval is { } i) o.RevokedSids.PollInterval = i;
        return Options.Create(o);
    }

    /// <summary>
    /// Waits until the fake has seen the bootstrap poll, or five seconds have passed. The service
    /// makes that call on its own schedule right after StartAsync; the test must wait for the event,
    /// not guess its timing.
    /// </summary>
    private static async Task WaitForFirstCallAsync(FakeBackchannel fake)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (fake.Calls.Count == 0 && DateTime.UtcNow < deadline)
            await Task.Delay(10);
    }

    [Fact]
    public async Task Initial_poll_calls_client_with_null_cursor_and_applies_entries()
    {
        var fake = new FakeBackchannel();
        var cache = new RevokedSidsCache();
        var nextCursor = DateTimeOffset.UtcNow.AddSeconds(-1);
        var future = DateTimeOffset.UtcNow.AddHours(1);

        fake.Responder = cursor => new RevokedSidsSinceResponse
        {
            Entries = new List<RevokedSidEntry>
            {
                new RevokedSidEntry
                {
                    Sid = "sid-1",
                    Sub = null,
                    ClientId = null,
                    RevokedAt = DateTimeOffset.UtcNow,
                    ExpiresAt = future,
                },
            },
            NextCursor = nextCursor,
        };

        // Long interval so the PeriodicTimer never fires before we cancel.
        var svc = new RevokedSidsPollHostedService(
            fake, cache, Opts(TimeSpan.FromMinutes(10)), NullLogger<RevokedSidsPollHostedService>.Instance);

        using var cts = new CancellationTokenSource();
        var run = svc.StartAsync(cts.Token);

        // Wait for the bootstrap poll itself, not for a fixed 50 ms: on a loaded machine (a full
        // gate next door) the first call of the hosted service lands later, and a fixed sleep turns
        // that into a false failure. Bounded, so a service that never polls still fails.
        await WaitForFirstCallAsync(fake);
        await cts.CancelAsync();
        await svc.StopAsync(CancellationToken.None);

        fake.Calls.Should().NotBeEmpty();
        fake.Calls[0].Should().BeNull("the bootstrap poll must omit the cursor");
        cache.IsRevoked("sid-1", null).Should().BeTrue();
        cache.Cursor.Should().Be(nextCursor);
    }

    [Fact]
    public async Task Poll_failure_is_swallowed_and_cache_remains_consistent()
    {
        var fake = new FakeBackchannel
        {
            Responder = _ => throw new InvalidOperationException("simulated network failure"),
        };
        var cache = new RevokedSidsCache();

        var svc = new RevokedSidsPollHostedService(
            fake, cache, Opts(TimeSpan.FromMinutes(10)), NullLogger<RevokedSidsPollHostedService>.Instance);

        using var cts = new CancellationTokenSource();
        var run = svc.StartAsync(cts.Token);

        // Same rule as above: wait for the poll to have been attempted, do not guess 50 ms. Without
        // the call this test proves nothing - no poll, no exception, and every assertion below holds.
        await WaitForFirstCallAsync(fake);
        await cts.CancelAsync();

        // The service must not surface the exception via StopAsync.
        var act = async () => await svc.StopAsync(CancellationToken.None);
        await act.Should().NotThrowAsync();

        fake.Calls.Should().NotBeEmpty("the failing poll must have been attempted, otherwise the swallow path was never exercised");
        cache.Cursor.Should().BeNull();
    }

    [Fact]
    public async Task Without_backchannel_secret_the_poll_is_disabled_and_never_calls()
    {
        var fake = new FakeBackchannel();
        var cache = new RevokedSidsCache();

        // A 20 ms interval: were the poll enabled, a 300 ms window would show a dozen calls, so an
        // empty call log is a real observation, not a lucky one.
        var svc = new RevokedSidsPollHostedService(
            fake, cache, Opts(TimeSpan.FromMilliseconds(20), withSecret: false),
            NullLogger<RevokedSidsPollHostedService>.Instance);

        using var cts = new CancellationTokenSource();
        var run = svc.StartAsync(cts.Token);
        await Task.Delay(300);
        await cts.CancelAsync();
        await svc.StopAsync(CancellationToken.None);

        fake.Calls.Should().BeEmpty(
            "without Identity:BackchannelClient:ClientSecret the service must not poll at all - it cannot "
            + "authenticate, and a failing poll every interval would only spam the log");
        cache.Cursor.Should().BeNull();
    }
}
