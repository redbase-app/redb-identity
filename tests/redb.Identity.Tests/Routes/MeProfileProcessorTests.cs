using FluentAssertions;
using redb.Identity.Core.Routes.Processors;
using redb.Route.Core;
using Xunit;

namespace redb.Identity.Tests.Routes;

/// <summary>
/// H3 (v1.0 DoD §6) unit tests for <see cref="MeProfileProcessor"/>. Covers the
/// caller-id precondition paths (missing / non-positive) which reject <b>before</b>
/// any <see cref="IRouteContext"/> access, so no DB or service wiring is required.
/// Happy-path read/update flows live in the integration suite.
/// </summary>
public sealed class MeProfileProcessorTests
{
    private static Exchange BuildExchange(long? userId, string operation, object? body = null)
    {
        var ex = new Exchange(new Message { Body = body ?? new Dictionary<string, object?>() });
        ex.In.Headers["operation"] = operation;
        if (userId is not null)
            ex.Properties["identity:management-user-id"] = userId.Value;
        return ex;
    }

    [Fact]
    public async Task MissingSubject_Returns401()
    {
        var sut = new MeProfileProcessor(context: null!, redbName: null);
        var ex = BuildExchange(userId: null, operation: "read");

        await sut.Process(ex);

        ex.HasOut.Should().BeTrue();
        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(401);
        ex.IsStopped.Should().BeTrue();
        var body = (Dictionary<string, object?>)ex.Out.Body!;
        body["error"].Should().Be("invalid_token");
    }

    [Fact]
    public async Task NonPositiveSubject_Returns401()
    {
        var sut = new MeProfileProcessor(context: null!, redbName: null);
        var ex = BuildExchange(userId: 0, operation: "update");

        await sut.Process(ex);

        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(401);
    }

    [Fact]
    public async Task NegativeSubject_Returns401()
    {
        var sut = new MeProfileProcessor(context: null!, redbName: null);
        var ex = BuildExchange(userId: -7, operation: "read");

        await sut.Process(ex);

        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(401);
    }
}
