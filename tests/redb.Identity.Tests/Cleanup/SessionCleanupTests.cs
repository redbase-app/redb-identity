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
    public async Task Prune_WithBackgroundDeletion_UsesClusterSafePath()
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
        await _bgDeletion.Received(1).DeleteAsync(
            Arg.Is<IEnumerable<long>>(ids => ids.Count() == 2 && ids.Contains(1L) && ids.Contains(2L)),
            Arg.Any<IRedbUser>(), Arg.Any<int>(), Arg.Any<long?>());
        await _redb.DidNotReceive().DeleteAsync(Arg.Any<IEnumerable<long>>());
    }

    [Fact]
    public async Task Prune_WithoutBackgroundDeletion_FallsBackToSoftDelete()
    {
        var sessions = new List<RedbObject<SessionProps>>
        {
            CreateSession(10, "revoked", daysOld: 60),
            CreateSession(11, "revoked", daysOld: 45)
        };
        MockRedbQuery.Setup(_redb, sessions);
        _redb.SoftDeleteAsync(Arg.Any<IEnumerable<long>>(), Arg.Any<long?>())
            .Returns(new DeletionMark(0, 2));

        var processor = CreateProcessor(bgDeletion: null);
        var exchange = new TestExchange();
        await processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((int)body.prunedSessions).Should().Be(2);
        await _redb.Received(1).SoftDeleteAsync(
            Arg.Is<IEnumerable<long>>(ids => ids.Count() == 2 && ids.Contains(10L) && ids.Contains(11L)),
            Arg.Any<long?>());
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
        await _bgDeletion.DidNotReceive().DeleteAsync(
            Arg.Any<IEnumerable<long>>(), Arg.Any<IRedbUser>(), Arg.Any<int>(), Arg.Any<long?>());
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
