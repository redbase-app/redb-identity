using FluentAssertions;
using redb.Identity.Core.Routes.Processors;
using redb.Route.Core;
using Xunit;

namespace redb.Identity.Tests.Routes;

/// <summary>
/// B8 — IDOR fix verification. Exercises <see cref="RequireSelfOrAdminProcessor"/>
/// directly with synthetic <see cref="Exchange"/> objects to validate the
/// self-vs-admin authorization rule without spinning up the full HTTP stack.
/// </summary>
public sealed class MfaIdorTests
{
    private const string AdminScope = "identity:manage";
    private const string AccountScope = "identity:account";

    private static RequireSelfOrAdminProcessor CreateSut() =>
        new(AdminScope, AccountScope);

    private static Exchange BuildExchange(long? bodyUserId, long? callerUserId, string[]? scopes)
    {
        var body = bodyUserId.HasValue
            ? new Dictionary<string, object?> { ["userId"] = bodyUserId.Value }
            : new Dictionary<string, object?>();
        var msg = new Message { Body = body };
        var ex = new Exchange(msg);
        if (scopes is not null)
            ex.Properties["identity:management-scopes"] = scopes;
        if (callerUserId is not null)
            ex.Properties["identity:management-user-id"] = callerUserId.Value;
        return ex;
    }

    [Fact]
    public async Task SelfScope_WithMatchingSubject_AllowsRequest()
    {
        var sut = CreateSut();
        var ex = BuildExchange(bodyUserId: 42, callerUserId: 42, scopes: new[] { AccountScope });

        await sut.Process(ex);

        ex.HasOut.Should().BeFalse();
        ex.IsStopped.Should().BeFalse();
    }

    [Fact]
    public async Task SelfScope_TargetingOtherUser_IsForbidden_NoLeakage()
    {
        var sut = CreateSut();
        var ex = BuildExchange(bodyUserId: 99, callerUserId: 42, scopes: new[] { AccountScope });

        await sut.Process(ex);

        ex.HasOut.Should().BeTrue();
        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(403);
        ex.IsStopped.Should().BeTrue();

        // C4: application-level authorization denials use RFC 9457 Problem Details
        // (the RFC 6750 OAuth error envelope is produced upstream by ManagementBearerAuth
        // for scope/token failures; this processor enforces an application IDOR guard
        // which is not an OAuth concept and therefore uses problem+json).
        ex.Out!.ContentType.Should().Be("application/problem+json");

        // Generic message — must not distinguish "no such user" from "not authorized".
        // The stable machine token is preserved as the RFC 9457 `code` extension member.
        var bodyText = System.Text.Encoding.UTF8.GetString((byte[])ex.Out!.Body!);
        bodyText.Should().Contain("not_authorized");
        bodyText.Should().NotContain("99");
        bodyText.Should().NotContain("42");
    }

    [Fact]
    public async Task AdminScope_TargetingOtherUser_IsAllowed()
    {
        var sut = CreateSut();
        var ex = BuildExchange(bodyUserId: 99, callerUserId: 42, scopes: new[] { AdminScope });

        await sut.Process(ex);

        ex.HasOut.Should().BeFalse();
        ex.IsStopped.Should().BeFalse();
    }

    [Fact]
    public async Task BothScopes_AdminWins_AllowsAnyUser()
    {
        var sut = CreateSut();
        var ex = BuildExchange(bodyUserId: 99, callerUserId: 42, scopes: new[] { AccountScope, AdminScope });

        await sut.Process(ex);

        ex.HasOut.Should().BeFalse();
        ex.IsStopped.Should().BeFalse();
    }

    [Fact]
    public async Task SelfScope_BodyMissingUserId_IsForbidden()
    {
        var sut = CreateSut();
        var ex = BuildExchange(bodyUserId: null, callerUserId: 42, scopes: new[] { AccountScope });

        await sut.Process(ex);

        ex.HasOut.Should().BeTrue();
        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(403);
        ex.IsStopped.Should().BeTrue();
    }

    [Fact]
    public async Task SelfScope_MissingCallerUserId_IsForbidden()
    {
        // client_credentials tokens have no internal user-id mirrored. Self-service
        // requires an end-user grant — without a caller user-id we MUST deny.
        var sut = CreateSut();
        var ex = BuildExchange(bodyUserId: 42, callerUserId: null, scopes: new[] { AccountScope });

        await sut.Process(ex);

        ex.HasOut.Should().BeTrue();
        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(403);
        ex.IsStopped.Should().BeTrue();
    }

    [Fact]
    public async Task NoAuthContext_InternalDirectVm_BypassesCheck()
    {
        // Calls coming via direct-vm without going through ManagementBearerAuthProcessor
        // (e.g. internal service-to-service / tests) carry no scopes property and must be
        // allowed through — direct-vm is not network-reachable.
        var sut = CreateSut();
        var ex = BuildExchange(bodyUserId: 42, callerUserId: null, scopes: null);

        await sut.Process(ex);

        ex.HasOut.Should().BeFalse();
        ex.IsStopped.Should().BeFalse();
    }

    [Fact]
    public async Task UnknownScope_NeitherAdminNorSelf_IsForbidden()
    {
        // Defensive: even if upstream auth admitted some other scope (e.g. scim only),
        // self-or-admin must still deny.
        var sut = CreateSut();
        var ex = BuildExchange(bodyUserId: 42, callerUserId: 42, scopes: new[] { "scim" });

        await sut.Process(ex);

        ex.HasOut.Should().BeTrue();
        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(403);
        ex.IsStopped.Should().BeTrue();
    }
}
