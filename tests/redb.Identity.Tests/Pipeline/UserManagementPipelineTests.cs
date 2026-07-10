using FluentAssertions;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using redb.Core.Models.Contracts;
using redb.Core.Models.Entities;
using redb.Identity.Contracts.Users;
using redb.Identity.Core.Models;
using redb.Identity.Contracts.Routes;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using CoreCreateUserRequest = redb.Core.Models.Users.CreateUserRequest;

namespace redb.Identity.Tests.Pipeline;

/// <summary>
/// User management through the full route pipeline including WireTap event dispatch.
/// </summary>
[Collection("IdentityRoute")]
public class UserManagementPipelineTests
{
    private readonly IdentityRouteFixture _fixture;

    public UserManagementPipelineTests(IdentityRouteFixture fixture) => _fixture = fixture;

    private static IRedbUser MockUser(long id, string login, bool enabled = true, string? name = null)
    {
        var user = NSubstitute.Substitute.For<IRedbUser>();
        user.Id.Returns(id);
        user.Login.Returns(login);
        user.Name.Returns(name ?? login);
        user.Enabled.Returns(enabled);
        user.DateRegister.Returns(DateTimeOffset.UtcNow);
        return user;
    }

    [Fact]
    public async Task CreateUser_ThroughPipeline_ReturnsUserResponse()
    {
        var coreUser = MockUser(10, "pipeline-user", name: "Pipeline User");
        _fixture.Redb.UserProvider.CreateUserAsync(Arg.Any<CoreCreateUserRequest>(), Arg.Any<IRedbUser?>())
            .Returns(coreUser);
        _fixture.Redb.SaveAsync(Arg.Any<RedbObject<UserProps>>()).Returns(100L);

        var exchange = await _fixture.RequestWithHeaders(
            IdentityEndpoints.ManageUsers,
            new CreateUserRequest
            {
                Login = "pipeline-user",
                Password = "P@ssw0rd!",
                DisplayName = "Pipeline User"
            },
            new Dictionary<string, object?> { ["operation"] = "create" });

        exchange.Exception.Should().BeNull();
        var resp = exchange.In.Body.Should().BeOfType<UserResponse>().Subject;
        resp.Login.Should().Be("pipeline-user");
    }

    [Fact]
    public async Task CreateUser_PasswordDelegatedToCore()
    {
        var coreUser = MockUser(11, "hash-test");
        _fixture.Redb.UserProvider.CreateUserAsync(Arg.Any<CoreCreateUserRequest>(), Arg.Any<IRedbUser?>())
            .Returns(coreUser);
        _fixture.Redb.SaveAsync(Arg.Any<RedbObject<UserProps>>()).Returns(100L);

        var exchange = await _fixture.RequestWithHeaders(
            IdentityEndpoints.ManageUsers,
            new CreateUserRequest { Login = "hash-test", Password = "secret123" },
            new Dictionary<string, object?> { ["operation"] = "create" });

        exchange.Exception.Should().BeNull();
        // Verify password was passed to Core provider (which handles hashing)
        await _fixture.Redb.UserProvider.Received(1).CreateUserAsync(
            Arg.Is<CoreCreateUserRequest>(r => r.Password == "secret123"),
            Arg.Any<IRedbUser?>());
    }

    [Fact]
    public async Task CreateUser_MissingLogin_ReturnsValidationError()
    {
        var exchange = await _fixture.RequestWithHeaders(
            IdentityEndpoints.ManageUsers,
            new CreateUserRequest { Login = "", Password = "pass1234" },
            new Dictionary<string, object?> { ["operation"] = "create" });

        exchange.Exception.Should().BeNull();
        var body = (dynamic)exchange.In.Body!;
        ((string)body.error).Should().Be("validation_error");
    }

    [Fact]
    public async Task ChangePassword_ThroughPipeline_Works()
    {
        var coreUser = MockUser(20, "pwd-user");
        _fixture.Redb.UserProvider.GetUserByIdAsync(20).Returns(coreUser);
        _fixture.Redb.UserProvider.ChangePasswordAsync(coreUser, "old-pass", "new-pass", Arg.Any<IRedbUser?>())
            .Returns(true);
        // C7: ChangePassword now triggers SessionService.LogoutAsync — stub session/auth
        // queries with empty in-memory lists so the mock chain doesn't NRE.
        MockRedbQuery.Setup(_fixture.Redb, new List<RedbObject<SessionProps>>());
        MockRedbQuery.Setup(_fixture.Redb, new List<RedbObject<AuthorizationProps>>());

        var exchange = await _fixture.RequestWithHeaders(
            IdentityEndpoints.ManageUsers,
            new ChangePasswordRequest { Id = 20, OldPassword = "old-pass", NewPassword = "new-pass" },
            new Dictionary<string, object?> { ["operation"] = "change-password" });

        exchange.Exception.Should().BeNull();
        var body = (dynamic)exchange.In.Body!;
        ((bool)body.success).Should().BeTrue();
    }

    [Fact]
    public async Task ChangePassword_WrongOldPassword_ReturnsError()
    {
        var coreUser = MockUser(21, "pwd-user2");
        _fixture.Redb.UserProvider.GetUserByIdAsync(21).Returns(coreUser);
        _fixture.Redb.UserProvider.ChangePasswordAsync(coreUser, "wrong-pass", "new-pass", Arg.Any<IRedbUser?>())
            .Returns(false);

        var exchange = await _fixture.RequestWithHeaders(
            IdentityEndpoints.ManageUsers,
            new ChangePasswordRequest { Id = 21, OldPassword = "wrong-pass", NewPassword = "new-pass" },
            new Dictionary<string, object?> { ["operation"] = "change-password" });

        exchange.Exception.Should().BeNull();
        var body = (dynamic)exchange.In.Body!;
        ((string)body.error).Should().Be("invalid_password");
    }

    [Fact]
    public async Task MissingOperationHeader_ThroughPipeline_ErrorHandled()
    {
        // No "operation" header → processor throws InvalidOperationException → caught by OnException<Exception>
        var exchange = await _fixture.RequestWithHeaders(
            IdentityEndpoints.ManageUsers,
            new CreateUserRequest { Login = "x", Password = "pass1234" },
            new Dictionary<string, object?>());

        // The builder-level OnException<Exception> catches this and returns server_error
        var body = exchange.In.Body;
        body.Should().NotBeNull();
        if (body is Dictionary<string, object> dict)
        {
            dict.Should().ContainKey("error");
            dict["error"].Should().Be("server_error");
        }
    }
}
