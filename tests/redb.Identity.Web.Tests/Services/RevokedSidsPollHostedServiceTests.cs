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

    private static IOptions<IdentityWebOptions> Opts(TimeSpan? interval = null)
    {
        var o = new IdentityWebOptions();
        if (interval is { } i) o.RevokedSids.PollInterval = i;
        return Options.Create(o);
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

        // Give the initial bootstrap poll a chance to complete.
        await Task.Delay(50);
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

        await Task.Delay(50);
        await cts.CancelAsync();

        // The service must not surface the exception via StopAsync.
        var act = async () => await svc.StopAsync(CancellationToken.None);
        await act.Should().NotThrowAsync();

        cache.Cursor.Should().BeNull();
    }
}
