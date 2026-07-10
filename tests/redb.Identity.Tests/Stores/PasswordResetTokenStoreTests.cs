using System;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using redb.Core;
using redb.Identity.Core.Models;
using redb.Identity.Core.PasswordReset;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;

namespace redb.Identity.Tests.Stores;

/// <summary>
/// N-4 (Session C.1): integration tests for <see cref="RedbPasswordResetTokenStore"/>.
/// Mirrors the invariant set of <c>PropsServerSideOtpStore</c>: issue → consume single-use,
/// already-consumed / expired / bad-token / unknown-jti rejection paths, peppered hashing.
/// Runs against the real Postgres-backed <see cref="PostgresFixture"/>.
/// </summary>
[Collection("Postgres")]
public class PasswordResetTokenStoreTests : IAsyncLifetime
{
    private readonly PostgresFixture _fixture;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly RedbPasswordResetTokenStore _store;
    private readonly FixedClock _clock;

    public PasswordResetTokenStoreTests(PostgresFixture fixture)
    {
        _fixture = fixture;
        _scopeFactory = fixture.Services.GetRequiredService<IServiceScopeFactory>();
        _clock = new FixedClock(DateTimeOffset.Parse("2026-05-17T10:00:00Z"));
        _store = new RedbPasswordResetTokenStore(
            _scopeFactory,
            RecoveryCodePepperProvider.ForTesting(new byte[] {
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
            }),
            NullLogger<RedbPasswordResetTokenStore>.Instance,
            _clock);
    }

    public async Task InitializeAsync()
    {
        await _fixture.Redb.SyncSchemeAsync<PasswordResetTokenProps>();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Issue_ReturnsUniqueJti_PlaintextToken_AndExpiresAt()
    {
        var ttl = TimeSpan.FromMinutes(30);

        var a = await _store.IssueAsync(userId: 42, callerResetUrl: "https://app.example.com/reset", ttl);
        var b = await _store.IssueAsync(userId: 42, callerResetUrl: "https://app.example.com/reset", ttl);

        a.Jti.Should().NotBe(Guid.Empty);
        b.Jti.Should().NotBe(Guid.Empty);
        a.Jti.Should().NotBe(b.Jti);
        a.PlaintextToken.Should().NotBeNullOrEmpty();
        a.PlaintextToken.Should().NotBe(b.PlaintextToken);
        a.ExpiresAt.Should().Be(_clock.GetUtcNow() + ttl);
    }

    [Fact]
    public async Task Issue_PersistsRowWithHashedToken_NotPlaintext()
    {
        var issued = await _store.IssueAsync(123, "https://app.example.com/reset", TimeSpan.FromMinutes(30));

        await using var scope = _scopeFactory.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var key = issued.Jti.ToString("N");
        var row = await redb.Query<PasswordResetTokenProps>()
            .Where(p => p.Jti == key)
            .FirstOrDefaultAsync();

        row.Should().NotBeNull();
        row!.Props.UserId.Should().Be(123);
        row.Props.TokenHash.Should().NotBe(issued.PlaintextToken);
        row.Props.TokenHash.Should().MatchRegex("^[0-9a-f]{64}$");
        row.Props.Consumed.Should().BeFalse();
        row.Props.Attempts.Should().Be(0);
        row.Props.CallerResetUrl.Should().Be("https://app.example.com/reset");
    }

    [Fact]
    public async Task VerifyAndConsume_WithCorrectToken_Succeeds_AndReturnsUserId()
    {
        var issued = await _store.IssueAsync(777, "https://app.example.com/reset", TimeSpan.FromMinutes(30));

        var result = await _store.VerifyAndConsumeAsync(issued.Jti, issued.PlaintextToken);

        result.Success.Should().BeTrue();
        result.UserId.Should().Be(777);
        result.Reason.Should().Be("ok");
    }

    [Fact]
    public async Task VerifyAndConsume_Twice_SecondCallReportsAlreadyConsumed()
    {
        var issued = await _store.IssueAsync(7, "https://app.example.com/reset", TimeSpan.FromMinutes(30));
        var first = await _store.VerifyAndConsumeAsync(issued.Jti, issued.PlaintextToken);
        first.Success.Should().BeTrue();

        var second = await _store.VerifyAndConsumeAsync(issued.Jti, issued.PlaintextToken);

        second.Success.Should().BeFalse();
        second.UserId.Should().Be(0);
        second.Reason.Should().Be("already_consumed");
    }

    [Fact]
    public async Task VerifyAndConsume_WithBadToken_Fails_AndIncrementsAttempts()
    {
        var issued = await _store.IssueAsync(8, "https://app.example.com/reset", TimeSpan.FromMinutes(30));

        var result = await _store.VerifyAndConsumeAsync(issued.Jti, "wrong-token");

        result.Success.Should().BeFalse();
        result.UserId.Should().Be(0);
        result.Reason.Should().Be("bad_token");

        await using var scope = _scopeFactory.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var key = issued.Jti.ToString("N");
        var row = await redb.Query<PasswordResetTokenProps>()
            .Where(p => p.Jti == key)
            .FirstOrDefaultAsync();
        row!.Props.Attempts.Should().Be(1);
        row.Props.Consumed.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyAndConsume_WithUnknownJti_ReturnsNotFound()
    {
        var result = await _store.VerifyAndConsumeAsync(Guid.NewGuid(), "any-token");

        result.Success.Should().BeFalse();
        result.UserId.Should().Be(0);
        result.Reason.Should().Be("not_found");
    }

    [Fact]
    public async Task VerifyAndConsume_WithEmptyJti_ReturnsNotFound()
    {
        var result = await _store.VerifyAndConsumeAsync(Guid.Empty, "any-token");
        result.Reason.Should().Be("not_found");
    }

    [Fact]
    public async Task VerifyAndConsume_WithEmptyToken_ReturnsBadToken()
    {
        var result = await _store.VerifyAndConsumeAsync(Guid.NewGuid(), "");
        result.Reason.Should().Be("bad_token");
    }

    [Fact]
    public async Task VerifyAndConsume_AfterExpiry_ReturnsExpired()
    {
        var issued = await _store.IssueAsync(9, "https://app.example.com/reset", TimeSpan.FromMinutes(30));

        // Advance the clock past expiry.
        _clock.UtcNow = issued.ExpiresAt + TimeSpan.FromSeconds(1);

        var result = await _store.VerifyAndConsumeAsync(issued.Jti, issued.PlaintextToken);

        result.Success.Should().BeFalse();
        result.UserId.Should().Be(0);
        result.Reason.Should().Be("expired");
    }

    /// <summary>
    /// Test-only <see cref="TimeProvider"/> with a mutable instant so individual tests can
    /// advance time past TTL deterministically.
    /// </summary>
    private sealed class FixedClock : TimeProvider
    {
        public DateTimeOffset UtcNow { get; set; }
        public FixedClock(DateTimeOffset now) { UtcNow = now; }
        public override DateTimeOffset GetUtcNow() => UtcNow;
    }
}
