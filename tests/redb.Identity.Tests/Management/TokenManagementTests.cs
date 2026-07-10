using FluentAssertions;
using NSubstitute;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Tokens;
using redb.Identity.Core.Models;
using redb.Identity.Core.Routes.Processors;
using redb.Identity.Tests.Infrastructure;
using redb.Route.Abstractions;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace redb.Identity.Tests.Management;

public class TokenManagementTests
{
    private readonly IRedbService _redb = Substitute.For<IRedbService>();
    private readonly TokenManagementProcessor _processor;

    public TokenManagementTests()
    {
        var context = MockRouteContext.Create(_redb);
        _processor = new TokenManagementProcessor(context);
    }

    private static TestExchange CreateExchange(string operation, object? body = null)
    {
        var exchange = new TestExchange();
        exchange.In.Headers["operation"] = operation;
        if (body != null) exchange.In.Body = body;
        return exchange;
    }

    // ── List ──

    [Fact]
    public async Task List_NoFilters_ReturnsAllTokens()
    {
        var items = new List<RedbObject<TokenProps>>
        {
            MockRedbQuery.CreateObject<TokenProps>(1, "token1",
                new TokenProps { ApplicationObjectId = 10, Status = Statuses.Valid, Type = "access_token" }),
            MockRedbQuery.CreateObject<TokenProps>(2, "token2",
                new TokenProps { ApplicationObjectId = 10, Status = Statuses.Revoked, Type = "refresh_token" })
        };
        MockRedbQuery.Setup(_redb, items);

        var exchange = CreateExchange("list");

        await _processor.Process(exchange);

        var result = exchange.Out!.Body.Should().BeOfType<PagedResult<TokenInfoResponse>>().Subject;
        result.Total.Should().Be(2);
        result.Items.Should().HaveCount(2);
    }

    [Fact]
    public async Task List_FilterByStatus_ReturnsFiltered()
    {
        var items = new List<RedbObject<TokenProps>>
        {
            MockRedbQuery.CreateObject<TokenProps>(1, "t1",
                new TokenProps { Status = Statuses.Valid, Type = "access_token" }),
            MockRedbQuery.CreateObject<TokenProps>(2, "t2",
                new TokenProps { Status = Statuses.Revoked, Type = "access_token" }),
            MockRedbQuery.CreateObject<TokenProps>(3, "t3",
                new TokenProps { Status = Statuses.Valid, Type = "refresh_token" })
        };
        MockRedbQuery.Setup(_redb, items);

        var exchange = CreateExchange("list", new Dictionary<string, object?>
        {
            ["status"] = Statuses.Valid
        });

        await _processor.Process(exchange);

        var result = exchange.Out!.Body.Should().BeOfType<PagedResult<TokenInfoResponse>>().Subject;
        result.Total.Should().Be(2);
        result.Items.Should().OnlyContain(t => t.Status == Statuses.Valid);
    }

    // ── Revoke ──

    [Fact]
    public async Task Revoke_ValidToken_SetsRevokedStatus()
    {
        var token = MockRedbQuery.CreateObject<TokenProps>(42, "tok",
            new TokenProps { Status = Statuses.Valid, Type = "access_token" });
        _redb.LoadAsync<TokenProps>(42).Returns(token);
        _redb.SaveAsync(Arg.Any<RedbObject<TokenProps>>()).Returns(42L);

        var exchange = CreateExchange("revoke", new Dictionary<string, object?> { ["tokenId"] = 42L });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((bool)body.success).Should().BeTrue();
        token.Props.Status.Should().Be(Statuses.Revoked);
        exchange.Properties["identity-event-type"].Should().Be("TokenRevoked");
    }

    [Fact]
    public async Task Revoke_MissingTokenId_ReturnsValidationError()
    {
        var exchange = CreateExchange("revoke", new Dictionary<string, object?> { ["tokenId"] = 0L });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("validation_error");
    }

    [Fact]
    public async Task Revoke_TokenNotFound_ReturnsNotFoundError()
    {
        _redb.LoadAsync<TokenProps>(999).Returns((RedbObject<TokenProps>?)null);

        var exchange = CreateExchange("revoke", new Dictionary<string, object?> { ["tokenId"] = 999L });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("not_found");
    }

    // ── Revoke by user ──

    [Fact]
    public async Task RevokeByUser_RevokesAllValidTokens()
    {
        // The processor first reads UserProps to resolve the public sub (value_guid),
        // then queries TokenProps by ValueGuid. Both queryables must be seeded.
        var userGuid = Guid.NewGuid();
        var userObj = MockRedbQuery.CreateObject<UserProps>(100, "u100", new UserProps());
        userObj.Key = 100;
        userObj.value_guid = userGuid;
        MockRedbQuery.Setup(_redb, new List<RedbObject<UserProps>> { userObj });

        var items = new List<RedbObject<TokenProps>>
        {
            MockRedbQuery.CreateObject<TokenProps>(1, "t1",
                new TokenProps { Status = Statuses.Valid, Type = "access_token" }),
            MockRedbQuery.CreateObject<TokenProps>(2, "t2",
                new TokenProps { Status = Statuses.Valid, Type = "refresh_token" })
        };
        // TokenProps subject linkage moved from Key→value_guid; mirror that on the seed.
        foreach (var t in items) t.value_guid = userGuid;
        MockRedbQuery.Setup(_redb, items);
        _redb.SaveAsync(Arg.Any<RedbObject<TokenProps>>()).Returns(ci => ci.Arg<RedbObject<TokenProps>>().Id);

        var exchange = CreateExchange("revoke-by-user", new Dictionary<string, object?> { ["userId"] = 100L });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((int)body.revokedCount).Should().Be(2);
        items.Should().OnlyContain(t => t.Props.Status == Statuses.Revoked);
        exchange.Properties["identity-event-type"].Should().Be("TokensRevokedByUser");
    }

    [Fact]
    public async Task RevokeByUser_MissingUserId_ReturnsValidationError()
    {
        var exchange = CreateExchange("revoke-by-user", new Dictionary<string, object?> { ["userId"] = 0L });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("validation_error");
    }

    // ── Unknown operation ──

    [Fact]
    public async Task UnknownOperation_ReturnsInvalidOperation()
    {
        var exchange = CreateExchange("destroy");

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("invalid_operation");
    }
}
