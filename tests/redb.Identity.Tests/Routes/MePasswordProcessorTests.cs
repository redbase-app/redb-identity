using FluentAssertions;
using redb.Identity.Contracts.Users;
using redb.Identity.Core.Routes.Processors;
using redb.Route.Core;
using Xunit;

namespace redb.Identity.Tests.Routes;

/// <summary>
/// H3 (v1.0 DoD §6) unit tests for <see cref="MePasswordProcessor"/>. Covers the
/// caller-id and request-body precondition paths which reject <b>before</b>
/// any <see cref="IRouteContext"/> access, so no DB or service wiring is required.
/// Happy-path change + session-revocation flow lives in the integration suite.
/// </summary>
public sealed class MePasswordProcessorTests
{
    private static Exchange BuildExchange(long? userId, object? body)
    {
        var ex = new Exchange(new Message { Body = body });
        ex.In.Headers["operation"] = "change";
        if (userId is not null)
            ex.Properties["identity:management-user-id"] = userId.Value;
        return ex;
    }

    [Fact]
    public async Task MissingSubject_Returns401()
    {
        var sut = new MePasswordProcessor(context: null!, redbName: null);
        var ex = BuildExchange(
            userId: null,
            body: new MeChangePasswordRequest { OldPassword = "old-pass-123", NewPassword = "new-pass-456" });

        await sut.Process(ex);

        ex.HasOut.Should().BeTrue();
        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(401);
        ex.IsStopped.Should().BeTrue();
        var body = (Dictionary<string, object?>)ex.Out.Body!;
        body["error"].Should().Be("invalid_token");
    }

    [Fact]
    public async Task InvalidBodyType_Returns400_ValidationError()
    {
        var sut = new MePasswordProcessor(context: null!, redbName: null);
        // Body is a generic dict, not MeChangePasswordRequest — must be rejected.
        var ex = BuildExchange(userId: 42, body: new Dictionary<string, object?>());

        await sut.Process(ex);

        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(400);
        var body = (Dictionary<string, object?>)ex.Out.Body!;
        body["error"].Should().Be("validation_error");
    }

    [Fact]
    public async Task EmptyOldPassword_Returns400()
    {
        var sut = new MePasswordProcessor(context: null!, redbName: null);
        var ex = BuildExchange(
            userId: 42,
            body: new MeChangePasswordRequest { OldPassword = "", NewPassword = "new-pass-456" });

        await sut.Process(ex);

        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(400);
        var body = (Dictionary<string, object?>)ex.Out.Body!;
        body["error"].Should().Be("validation_error");
        body["error_description"].Should().Be("OldPassword is required");
    }

    [Fact]
    public async Task WeakNewPassword_Returns400()
    {
        var sut = new MePasswordProcessor(context: null!, redbName: null);
        var ex = BuildExchange(
            userId: 42,
            body: new MeChangePasswordRequest { OldPassword = "old-pass-123", NewPassword = "x" });

        await sut.Process(ex);

        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(400);
        var body = (Dictionary<string, object?>)ex.Out.Body!;
        body["error"].Should().Be("validation_error");
        ((string)body["error_description"]!).Should().Contain("NewPassword");
    }

    [Fact]
    public async Task SameOldAndNewPassword_Returns400()
    {
        var sut = new MePasswordProcessor(context: null!, redbName: null);
        var ex = BuildExchange(
            userId: 42,
            body: new MeChangePasswordRequest { OldPassword = "same-pass-123", NewPassword = "same-pass-123" });

        await sut.Process(ex);

        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(400);
        var body = (Dictionary<string, object?>)ex.Out.Body!;
        body["error"].Should().Be("validation_error");
        ((string)body["error_description"]!).Should().Contain("differ");
    }
}
