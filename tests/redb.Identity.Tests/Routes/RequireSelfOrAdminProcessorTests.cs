using FluentAssertions;
using redb.Identity.Core.Routes.Processors;
using redb.Route.Abstractions;
using redb.Route.Core;
using Xunit;

namespace redb.Identity.Tests.Routes;

/// <summary>
/// The self-or-admin rule is an authorization gate, and a gate has one direction it must never fail.
/// An exchange with no management context is not an internal trusted caller — it is a caller nobody
/// authenticated — and it is refused like any other unauthorized one.
/// </summary>
public sealed class RequireSelfOrAdminProcessorTests
{
    private const string Admin = "identity:manage";
    private const string Account = "identity:account";

    private static Exchange Request(long bodyUserId, string[]? scopes, long? callerUserId = null)
    {
        var message = new Message { Body = new Dictionary<string, object?> { ["userId"] = bodyUserId } };
        var exchange = new Exchange(message) { Pattern = ExchangePattern.InOut };
        if (scopes is not null) exchange.Properties["identity:management-scopes"] = scopes;
        if (callerUserId is not null) exchange.Properties["identity:management-user-id"] = callerUserId.Value;
        return exchange;
    }

    private static int? StatusOf(IExchange exchange)
        => exchange.Out is { } o && o.Headers.TryGetValue("redbHttp.ResponseCode", out var raw) && raw is not null
            ? Convert.ToInt32(raw)
            : null;

    [Fact]
    public async Task No_management_context_is_refused()
    {
        var sut = new RequireSelfOrAdminProcessor(Admin, Account);
        var exchange = Request(bodyUserId: 42, scopes: null);

        await sut.Process(exchange);

        StatusOf(exchange).Should().Be(403,
            "absence of a management context means nobody authenticated this caller; it is not a trusted internal one");
    }

    [Fact]
    public async Task Admin_scope_passes()
    {
        var sut = new RequireSelfOrAdminProcessor(Admin, Account);
        var exchange = Request(bodyUserId: 42, scopes: new[] { Admin });

        await sut.Process(exchange);

        StatusOf(exchange).Should().BeNull();
    }

    [Fact]
    public async Task Account_scope_passes_only_for_the_caller_itself()
    {
        var sut = new RequireSelfOrAdminProcessor(Admin, Account);

        var self = Request(bodyUserId: 42, scopes: new[] { Account }, callerUserId: 42);
        await sut.Process(self);
        StatusOf(self).Should().BeNull("the body targets the caller");

        var other = Request(bodyUserId: 43, scopes: new[] { Account }, callerUserId: 42);
        await sut.Process(other);
        StatusOf(other).Should().Be(403, "the body targets another user");
    }
}
