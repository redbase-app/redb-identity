using FluentAssertions;
using redb.Identity.Core.Routes.Processors;
using redb.Route.Core;
using Xunit;

namespace redb.Identity.Tests.Routes;

/// <summary>
/// MFA-3 unit tests for <see cref="MeWebAuthnProcessor"/>. Mirrors
/// <see cref="MeMfaProcessorTests"/> — covers caller-id precondition paths which
/// reject <b>before</b> any DI scope is created, so no MfaService / IFido2 wiring is
/// required. Happy-path register/credentials/rename/delete flows live in the integration
/// suite where a real MfaService + IWebAuthnMfaMethod are wired.
/// </summary>
public sealed class MeWebAuthnProcessorTests
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
        var sut = new MeWebAuthnProcessor(sp: null!);
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
        var sut = new MeWebAuthnProcessor(sp: null!);
        var ex = BuildExchange(userId: -3, operation: "credentials");

        await sut.Process(ex);

        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(401);
    }
}
