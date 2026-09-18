using FluentAssertions;
using Microsoft.Extensions.Options;
using NSubstitute;
using redb.Core;
using redb.Core.Models.Contracts;
using redb.Core.Models.Entities;
using redb.Core.Services;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Identity.Core.Routes.Processors;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Cleanup;

public class SessionCleanupTests
{
    private readonly IRedbService _redb = Substitute.For<IRedbService>();
    private readonly IBackgroundDeletionService _bgDeletion = Substitute.For<IBackgroundDeletionService>();
    private readonly IRedbSecurityContext _secCtx = Substitute.For<IRedbSecurityContext>();

    public SessionCleanupTests()
    {
        var systemUser = new RedbUser { Id = 0, Login = "sys", Name = "System" };
        _secCtx.GetEffectiveUser().Returns(systemUser);
        _redb.SecurityContext.Returns(_secCtx);
        _bgDeletion.DeleteAsync(Arg.Any<IEnumerable<long>>(), Arg.Any<IRedbUser>(), Arg.Any<int>(), Arg.Any<long?>())
            .Returns(ci => new DeletionMark(999, ci.Arg<IEnumerable<long>>().Count()));
    }

    private static RedbObject<SessionProps> CreateSession(long id, string status, int daysOld)
    {
        var session = MockRedbQuery.CreateObject<SessionProps>(id, $"session-{id}",
            new SessionProps { Status = status });
        session.DateCreate = DateTimeOffset.UtcNow.AddDays(-daysOld);
        return session;
    }

    private SessionCleanupProcessor CreateProcessor(IBackgroundDeletionService? bgDeletion)
    {
        var options = Options.Create(new RedbIdentityOptions { SessionRetentionDays = 30 });
        var context = MockRouteContext.Create(_redb);
        return new SessionCleanupProcessor(context, options, backgroundDeletion: bgDeletion);
    }

    [Fact]
    public async Task Prune_MarksThroughTheCallerService_NotTheBackgroundConnection()
    {
        var sessions = new List<RedbObject<SessionProps>>
        {
            CreateSession(1, "revoked", daysOld: 60),
            CreateSession(2, "revoked", daysOld: 31),
            CreateSession(3, "active",  daysOld: 60)  // active → not pruned
        };
        MockRedbQuery.Setup(_redb, sessions);

        var processor = CreateProcessor(_bgDeletion);
        var exchange = new TestExchange();
        await processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((int)body.prunedSessions).Should().Be(2);
        exchange.Properties["identity-event-type"].Should().Be("SessionsPruned");
        // The mark is written by the CALLER's service so it joins whatever transaction the
        // caller is in. IBackgroundDeletionService.DeleteAsync would mark on a second
        // connection of its own — which deadlocks against a route transaction on SQLite and
        // commits outside it on PostgreSQL / MSSQL. The service still purges: it finds the
        // trash container by polling, nothing is handed to it.
        await _redb.Received(1).SoftDeleteAsync(
            Arg.Is<IEnumerable<long>>(ids => ids.Count() == 2 && ids.Contains(1L) && ids.Contains(2L)),
            Arg.Any<IRedbUser>(), Arg.Any<long?>(), Arg.Any<CancellationToken>());
        await _bgDeletion.DidNotReceive().DeleteAsync(
            Arg.Any<IEnumerable<long>>(), Arg.Any<IRedbUser>(), Arg.Any<int>(), Arg.Any<long?>());
        await _redb.DidNotReceive().DeleteAsync(Arg.Any<IEnumerable<long>>());
    }

    [Fact]
    public async Task Prune_WithoutBackgroundDeletion_StillMarks_ButNothingWillPurge()
    {
        var sessions = new List<RedbObject<SessionProps>>
        {
            CreateSession(10, "revoked", daysOld: 60),
            CreateSession(11, "revoked", daysOld: 45)
        };
        MockRedbQuery.Setup(_redb, sessions);
        _redb.SoftDeleteAsync(Arg.Any<IEnumerable<long>>(), Arg.Any<IRedbUser>(),
                Arg.Any<long?>(), Arg.Any<CancellationToken>())
            .Returns(new DeletionMark(0, 2));

        var processor = CreateProcessor(bgDeletion: null);
        var exchange = new TestExchange();
        await processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((int)body.prunedSessions).Should().Be(2);
        await _redb.Received(1).SoftDeleteAsync(
            Arg.Is<IEnumerable<long>>(ids => ids.Count() == 2 && ids.Contains(10L) && ids.Contains(11L)),
            Arg.Any<IRedbUser>(), Arg.Any<long?>(), Arg.Any<CancellationToken>());
        await _redb.DidNotReceive().DeleteAsync(Arg.Any<IEnumerable<long>>());
        await _bgDeletion.DidNotReceive().DeleteAsync(
            Arg.Any<IEnumerable<long>>(), Arg.Any<IRedbUser>(), Arg.Any<int>(), Arg.Any<long?>());
    }

    [Fact]
    public async Task Prune_SkipsSessionsWithinRetention()
    {
        var sessions = new List<RedbObject<SessionProps>>
        {
            CreateSession(1, "revoked", daysOld: 10),  // within 30 days
            CreateSession(2, "revoked", daysOld: 5)
        };
        MockRedbQuery.Setup(_redb, sessions);

        var processor = CreateProcessor(_bgDeletion);
        var exchange = new TestExchange();
        await processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((int)body.prunedSessions).Should().Be(0);
        // Assert on the path that actually marks. The background service is no longer called
        // at all, so an assertion only on it would hold even if a session HAD been deleted.
        await _redb.DidNotReceive().SoftDeleteAsync(
            Arg.Any<IEnumerable<long>>(), Arg.Any<IRedbUser>(), Arg.Any<long?>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Prune_EmptyDB_ReturnsZero()
    {
        MockRedbQuery.Setup(_redb, new List<RedbObject<SessionProps>>());

        var processor = CreateProcessor(_bgDeletion);
        var exchange = new TestExchange();
        await processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((int)body.prunedSessions).Should().Be(0);
    }
}
