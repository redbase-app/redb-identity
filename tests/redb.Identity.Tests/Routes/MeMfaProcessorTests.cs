using FluentAssertions;
using redb.Identity.Core.Routes.Processors;
using redb.Route.Core;
using Xunit;

namespace redb.Identity.Tests.Routes;

/// <summary>
/// H3 (v1.0 DoD §6) unit tests for <see cref="MeMfaProcessor"/>. Covers the
/// caller-id precondition paths which reject <b>before</b> the
/// <see cref="IServiceProvider"/> scope is created, so no DI wiring is required.
/// Happy-path setup/confirm/disable/regenerate flows live in the integration suite
/// where a real <see cref="redb.Identity.Core.Services.MfaService"/> is wired.
/// </summary>
public sealed class MeMfaProcessorTests
{
    private static Exchange BuildExchange(long? userId, string operation)
    {
        var ex = new Exchange(new Message { Body = new Dictionary<string, object?>() });
        ex.In.Headers["operation"] = operation;
        if (userId is not null)
            ex.Properties["identity:management-user-id"] = userId.Value;
        return ex;
    }

    [Fact]
    public async Task MissingSubject_Returns401()
    {
        var sut = new MeMfaProcessor(sp: null!);
        var ex = BuildExchange(userId: null, operation: "status");

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
        var sut = new MeMfaProcessor(sp: null!);
        var ex = BuildExchange(userId: 0, operation: "setup");

        await sut.Process(ex);

        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(401);
    }
}
