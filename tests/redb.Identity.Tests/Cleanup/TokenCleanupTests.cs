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
using redb.Route.Abstractions;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace redb.Identity.Tests.Cleanup;

public class TokenCleanupTests
{
    private readonly IRedbService _redb = Substitute.For<IRedbService>();
    private readonly IBackgroundDeletionService _bgDeletion = Substitute.For<IBackgroundDeletionService>();
    private readonly IRedbSecurityContext _secCtx = Substitute.For<IRedbSecurityContext>();
    private readonly TokenCleanupProcessor _processor;

    public TokenCleanupTests()
    {
        var options = Options.Create(new RedbIdentityOptions { TokenRetentionDays = 30 });
        var systemUser = new RedbUser { Id = 0, Login = "sys", Name = "System" };
        _secCtx.GetEffectiveUser().Returns(systemUser);
        _redb.SecurityContext.Returns(_secCtx);
        _bgDeletion.DeleteAsync(Arg.Any<IEnumerable<long>>(), Arg.Any<IRedbUser>(), Arg.Any<int>(), Arg.Any<long?>())
            .Returns(ci => new DeletionMark(999, ci.Arg<IEnumerable<long>>().Count()));
        var context = MockRouteContext.Create(_redb);
        _processor = new TokenCleanupProcessor(context, options, backgroundDeletion: _bgDeletion);
    }

    private static RedbObject<TokenProps> CreateToken(long id, string status, int daysOld, DateTimeOffset? dateComplete = null)
    {
        var token = MockRedbQuery.CreateObject<TokenProps>(id, $"token-{id}",
            new TokenProps { Status = status, Type = "access_token" });
        token.DateCreate = DateTimeOffset.UtcNow.AddDays(-daysOld);
        if (dateComplete.HasValue)
            token.DateComplete = dateComplete;
        return token;
    }

    [Fact]
    public async Task Prune_DeletesRevokedTokensOlderThanRetention()
    {
        var tokens = new List<RedbObject<TokenProps>>
        {
            CreateToken(1, Statuses.Revoked, daysOld: 60),
            CreateToken(2, Statuses.Revoked, daysOld: 31),
            CreateToken(3, Statuses.Valid, daysOld: 60)  // valid → not pruned by step 1
        };
        MockRedbQuery.Setup(_redb, tokens);
        MockRedbQuery.Setup(_redb, new List<RedbObject<AuthorizationProps>>());

        var exchange = new TestExchange();
        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((int)body.prunedTokens).Should().Be(2);
        exchange.Properties["identity-event-type"].Should().Be("TokensPruned");
        await _bgDeletion.Received(1).DeleteAsync(
            Arg.Is<IEnumerable<long>>(ids => ids.Count() == 2),
            Arg.Any<IRedbUser>(), Arg.Any<int>(), Arg.Any<long?>());
    }

    [Fact]
    public async Task Prune_SkipsTokensWithinRetention()
    {
        var tokens = new List<RedbObject<TokenProps>>
        {
            CreateToken(1, Statuses.Revoked, daysOld: 10),  // within 30 days
            CreateToken(2, Statuses.Revoked, daysOld: 5)    // within 30 days
        };
        MockRedbQuery.Setup(_redb, tokens);
        MockRedbQuery.Setup(_redb, new List<RedbObject<AuthorizationProps>>());

        var exchange = new TestExchange();
        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((int)body.prunedTokens).Should().Be(0);
        await _bgDeletion.DidNotReceive().DeleteAsync(
            Arg.Any<IEnumerable<long>>(), Arg.Any<IRedbUser>(), Arg.Any<int>(), Arg.Any<long?>());
    }

    [Fact]
    public async Task Prune_DeletesExpiredValidTokens()
    {
        var expired = DateTimeOffset.UtcNow.AddDays(-1); // expired yesterday
        var tokens = new List<RedbObject<TokenProps>>
        {
            CreateToken(1, Statuses.Valid, daysOld: 60, dateComplete: expired)
        };
        MockRedbQuery.Setup(_redb, tokens);
        MockRedbQuery.Setup(_redb, new List<RedbObject<AuthorizationProps>>());

        var exchange = new TestExchange();
        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((int)body.prunedTokens).Should().Be(1);
    }

    [Fact]
    public async Task Prune_EmptyDB_ReturnsZero()
    {
        MockRedbQuery.Setup(_redb, new List<RedbObject<TokenProps>>());
        MockRedbQuery.Setup(_redb, new List<RedbObject<AuthorizationProps>>());

        var exchange = new TestExchange();
        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((int)body.prunedTokens).Should().Be(0);
        ((int)body.prunedAuthorizations).Should().Be(0);
    }

    [Fact]
    public async Task Prune_PrunesOrphanedAuthorizations()
    {
        MockRedbQuery.Setup(_redb, new List<RedbObject<TokenProps>>());

        var auths = new List<RedbObject<AuthorizationProps>>
        {
            MockRedbQuery.CreateObject<AuthorizationProps>(100, "auth-1",
                new AuthorizationProps { Status = Statuses.Revoked })
        };
        auths[0].DateCreate = DateTimeOffset.UtcNow.AddDays(-60);
        MockRedbQuery.Setup(_redb, auths);

        // No tokens reference this authorization → orphaned

        var exchange = new TestExchange();
        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((int)body.prunedAuthorizations).Should().Be(1);
        await _bgDeletion.Received().DeleteAsync(
            Arg.Is<IEnumerable<long>>(ids => ids.Contains(100L)),
            Arg.Any<IRedbUser>(), Arg.Any<int>(), Arg.Any<long?>());
    }

    [Fact]
    public async Task Prune_KeepsAuthorizationsWithTokens()
    {
        // Token referencing authorization 100
        var tokens = new List<RedbObject<TokenProps>>
        {
            CreateToken(1, Statuses.Valid, daysOld: 5)
        };
        tokens[0].Props.AuthorizationObjectId = 100;
        MockRedbQuery.Setup(_redb, tokens);

        var auths = new List<RedbObject<AuthorizationProps>>
        {
            MockRedbQuery.CreateObject<AuthorizationProps>(100, "auth-1",
                new AuthorizationProps { Status = Statuses.Revoked })
        };
        auths[0].DateCreate = DateTimeOffset.UtcNow.AddDays(-60);
        MockRedbQuery.Setup(_redb, auths);

        var exchange = new TestExchange();
        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((int)body.prunedAuthorizations).Should().Be(0);
    }
}
