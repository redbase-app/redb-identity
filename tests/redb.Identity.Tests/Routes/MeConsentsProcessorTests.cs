using FluentAssertions;
using redb.Identity.Core.Routes.Processors;
using redb.Route.Core;
using Xunit;

namespace redb.Identity.Tests.Routes;

/// <summary>
/// H3 (v1.0 DoD §6) unit tests for <see cref="MeConsentsProcessor"/>. Covers the
/// token-subject precondition paths which reject <b>before</b> any
/// <see cref="IRouteContext"/> access, so no DB or service wiring is required.
/// Happy-path list + revoke flows (incl. ownership and 404-on-unknown-clientId)
/// live in the integration suite.
/// </summary>
public sealed class MeConsentsProcessorTests
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
    public async Task MissingSubject_List_Returns401()
    {
        var sut = new MeConsentsProcessor(context: null!, redbName: null);
        var ex = BuildExchange(userId: null, operation: "list");

        await sut.Process(ex);

        ex.HasOut.Should().BeTrue();
        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(401);
        ex.IsStopped.Should().BeTrue();
        var body = (Dictionary<string, object?>)ex.Out.Body!;
        body["error"].Should().Be("invalid_token");
    }

    [Fact]
    public async Task MissingSubject_Revoke_Returns401()
    {
        var sut = new MeConsentsProcessor(context: null!, redbName: null);
        var ex = BuildExchange(
            userId: null, operation: "revoke",
            body: new Dictionary<string, object?> { ["clientId"] = "demo-client" });

        await sut.Process(ex);

        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(401);
    }

    [Fact]
    public async Task NonPositiveSubject_Returns401()
    {
        var sut = new MeConsentsProcessor(context: null!, redbName: null);
        var ex = BuildExchange(userId: 0, operation: "list");

        await sut.Process(ex);

        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(401);
    }

    [Fact]
    public async Task Grant_MissingSubject_Returns401()
    {
        var sut = new MeConsentsProcessor(context: null!, redbName: null);
        var ex = BuildExchange(
            userId: null, operation: "grant",
            body: new Dictionary<string, object?>
            {
                ["clientId"] = "demo-client",
                ["scopes"] = new[] { "openid" },
            });

        await sut.Process(ex);

        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(401);
    }

    [Fact]
    public async Task Grant_MissingClientId_Returns400()
    {
        var sut = new MeConsentsProcessor(context: null!, redbName: null);
        var ex = BuildExchange(
            userId: 42, operation: "grant",
            body: new Dictionary<string, object?>
            {
                ["clientId"] = "  ",
                ["scopes"] = new[] { "openid" },
            });

        await sut.Process(ex);

        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(400);
        var body = (Dictionary<string, object?>)ex.Out.Body!;
        body["error"].Should().Be("validation_error");
    }

    [Fact]
    public async Task Grant_MissingScopes_Returns400()
    {
        var sut = new MeConsentsProcessor(context: null!, redbName: null);
        var ex = BuildExchange(
            userId: 42, operation: "grant",
            body: new Dictionary<string, object?>
            {
                ["clientId"] = "demo-client",
                ["scopes"] = Array.Empty<string>(),
            });

        await sut.Process(ex);

        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(400);
        var body = (Dictionary<string, object?>)ex.Out.Body!;
        body["error"].Should().Be("validation_error");
    }
}
