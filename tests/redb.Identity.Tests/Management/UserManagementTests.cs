using FluentAssertions;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using redb.Core;
using redb.Core.Models.Contracts;
using redb.Core.Models.Entities;
using redb.Core.Providers;
using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Users;
using redb.Identity.Core.Models;
using redb.Identity.Core.Routes.Processors;
using redb.Identity.Tests.Infrastructure;
using redb.Route.Abstractions;
using Xunit;
using CoreCreateUserRequest = redb.Core.Models.Users.CreateUserRequest;
using CoreUpdateUserRequest = redb.Core.Models.Users.UpdateUserRequest;

namespace redb.Identity.Tests.Management;

public class UserManagementTests
{
    private readonly IRedbService _redb = Substitute.For<IRedbService>();
    private readonly IUserProvider _userProvider = Substitute.For<IUserProvider>();
    private readonly UserManagementProcessor _processor;

    public UserManagementTests()
    {
        _redb.UserProvider.Returns(_userProvider);
        var context = MockRouteContext.Create(_redb);
        _processor = new UserManagementProcessor(context);
    }

    private static TestExchange CreateExchange(string operation, object? body = null)
    {
        var exchange = new TestExchange();
        exchange.In.Headers["operation"] = operation;
        if (body != null) exchange.In.Body = body;
        return exchange;
    }

    private static IRedbUser MockUser(long id, string login, bool enabled = true,
        string? email = null, string? phone = null, string? name = null)
    {
        var user = Substitute.For<IRedbUser>();
        user.Id.Returns(id);
        user.Login.Returns(login);
        user.Name.Returns(name ?? login);
        user.Enabled.Returns(enabled);
        user.Email.Returns(email);
        user.Phone.Returns(phone);
        user.DateRegister.Returns(DateTimeOffset.UtcNow);
        return user;
    }

    // ── Create ──

    [Fact]
    public async Task Create_ValidInput_ReturnsUserResponse()
    {
        var coreUser = MockUser(1, "admin", name: "Administrator");
        _userProvider.CreateUserAsync(Arg.Any<CoreCreateUserRequest>(), Arg.Any<IRedbUser?>())
            .Returns(coreUser);
        _redb.SaveAsync(Arg.Any<RedbObject<UserProps>>()).Returns(100L);

        var exchange = CreateExchange("create", new CreateUserRequest
        {
            Login = "admin",
            Password = "P@ssw0rd!",
            DisplayName = "Administrator"
        });

        await _processor.Process(exchange);

        var resp = exchange.Out!.Body.Should().BeOfType<UserResponse>().Subject;
        resp.Login.Should().Be("admin");
        resp.Status.Should().Be("active");
        exchange.Properties["identity-event-type"].Should().Be("UserCreated");
    }

    [Fact]
    public async Task Create_CoreHandlesPasswordHash()
    {
        var coreUser = MockUser(11, "user1");
        _userProvider.CreateUserAsync(Arg.Any<CoreCreateUserRequest>(), Arg.Any<IRedbUser?>())
            .Returns(coreUser);
        _redb.SaveAsync(Arg.Any<RedbObject<UserProps>>()).Returns(100L);

        var exchange = CreateExchange("create", new CreateUserRequest
        {
            Login = "user1",
            Password = "secret123"
        });

        await _processor.Process(exchange);

        // Password is delegated to Core's UserProvider — not stored in UserProps
        await _userProvider.Received(1).CreateUserAsync(
            Arg.Is<CoreCreateUserRequest>(r => r.Login == "user1" && r.Password == "secret123"),
            Arg.Any<IRedbUser?>());
    }

    [Fact]
    public async Task Create_MissingLogin_ReturnsValidationError()
    {
        var exchange = CreateExchange("create", new CreateUserRequest
        {
            Login = "",
            Password = "pass1234"
        });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("validation_error");
    }

    [Fact]
    public async Task Create_MissingPassword_ReturnsValidationError()
    {
        var exchange = CreateExchange("create", new CreateUserRequest
        {
            Login = "user1",
            Password = ""
        });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("validation_error");
    }

    [Fact]
    public async Task Create_DuplicateLogin_ReturnsDuplicateError()
    {
        _userProvider.CreateUserAsync(Arg.Any<CoreCreateUserRequest>(), Arg.Any<IRedbUser?>())
            .Throws(new InvalidOperationException("Login 'admin' is already taken"));

        var exchange = CreateExchange("create", new CreateUserRequest
        {
            Login = "admin",
            Password = "pass1234"
        });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("duplicate");
    }

    // ── Read ──

    [Fact]
    public async Task Read_ById_ReturnsUser()
    {
        var coreUser = MockUser(10, "admin", email: "admin@test.com");
        _userProvider.GetUserByIdAsync(10).Returns(coreUser);
        MockRedbQuery.Setup(_redb, new List<RedbObject<UserProps>>());

        var exchange = CreateExchange("read", new Dictionary<string, object?> { ["id"] = 10L });

        await _processor.Process(exchange);

        var resp = exchange.Out!.Body.Should().BeOfType<UserResponse>().Subject;
        resp.Login.Should().Be("admin");
        resp.Id.Should().Be(10);
    }

    [Fact]
    public async Task Read_ByLogin_ReturnsUser()
    {
        var coreUser = MockUser(10, "admin");
        _userProvider.GetUserByLoginAsync("admin").Returns(coreUser);
        MockRedbQuery.Setup(_redb, new List<RedbObject<UserProps>>());

        var exchange = CreateExchange("read", new Dictionary<string, object?> { ["login"] = "admin" });

        await _processor.Process(exchange);

        var resp = exchange.Out!.Body.Should().BeOfType<UserResponse>().Subject;
        resp.Login.Should().Be("admin");
    }

    [Fact]
    public async Task Read_NotFound_ReturnsNotFoundError()
    {
        _userProvider.GetUserByIdAsync(999).Returns((IRedbUser?)null);

        var exchange = CreateExchange("read", new Dictionary<string, object?> { ["id"] = 999L });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("not_found");
    }

    // ── Update ──

    [Fact]
    public async Task Update_ValidInput_ReturnsUpdatedUser()
    {
        var coreUser = MockUser(5, "user1");
        _userProvider.GetUserByIdAsync(5).Returns(coreUser);
        var updatedUser = MockUser(5, "user1", enabled: false, name: "New Name");
        _userProvider.UpdateUserAsync(coreUser, Arg.Any<CoreUpdateUserRequest>(), Arg.Any<IRedbUser?>())
            .Returns(updatedUser);
        MockRedbQuery.Setup(_redb, new List<RedbObject<UserProps>>());

        var exchange = CreateExchange("update", new UpdateUserRequest
        {
            Id = 5,
            DisplayName = "New Name",
            Status = "blocked"
        });

        await _processor.Process(exchange);

        var resp = exchange.Out!.Body.Should().BeOfType<UserResponse>().Subject;
        resp.DisplayName.Should().Be("New Name");
        resp.Status.Should().Be("blocked");
        exchange.Properties["identity-event-type"].Should().Be("UserUpdated");
    }

    [Fact]
    public async Task Update_InvalidStatus_ReturnsValidationError()
    {
        var coreUser = MockUser(5, "user1");
        _userProvider.GetUserByIdAsync(5).Returns(coreUser);

        var exchange = CreateExchange("update", new UpdateUserRequest
        {
            Id = 5,
            Status = "deleted"
        });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("validation_error");
    }

    // ── Delete ──

    [Fact]
    public async Task Delete_ValidId_ReturnsSuccess()
    {
        var coreUser = MockUser(7, "user7");
        _userProvider.GetUserByIdAsync(7).Returns(coreUser);
        _userProvider.DeleteUserAsync(coreUser, Arg.Any<IRedbUser?>()).Returns(true);
        MockRedbQuery.Setup(_redb, new List<RedbObject<UserProps>>());
        // Delete now cascades through SessionService.LogoutAsync (sessions + authorizations
        // revoke) before soft-deleting the user row — mock both query types so the cascade
        // doesn't NRE on an unconfigured Query<TProps>() call. Empty lists model the
        // "user has no active sessions / authorizations to revoke" path.
        MockRedbQuery.Setup(_redb, new List<RedbObject<SessionProps>>());
        MockRedbQuery.Setup(_redb, new List<RedbObject<AuthorizationProps>>());

        var exchange = CreateExchange("delete", new Dictionary<string, object?> { ["id"] = 7L });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((bool)body.success).Should().BeTrue();
        exchange.Properties["identity-event-type"].Should().Be("UserDeleted");
    }

    // ── List ──

    [Fact]
    public async Task List_ReturnsPaginatedResults()
    {
        var users = Enumerable.Range(1, 4)
            .Select(i => MockUser(i, $"user{i}"))
            .ToList();
        _userProvider.GetUsersAsync(Arg.Any<redb.Core.Models.Users.UserSearchCriteria>()).Returns(users);
        _userProvider.GetUserCountAsync().Returns(4);
        MockRedbQuery.Setup(_redb, new List<RedbObject<UserProps>>());

        var exchange = CreateExchange("list", new ListRequest { Offset = 0, Count = 2 });

        await _processor.Process(exchange);

        var result = exchange.Out!.Body.Should().BeOfType<PagedResult<UserResponse>>().Subject;
        result.Total.Should().Be(4);
        result.Items.Should().HaveCount(4);
    }

    // ── Search ──

    [Fact]
    public async Task Search_ByQuery_ReturnsMatchedUsers()
    {
        var users = new List<IRedbUser>
        {
            MockUser(1, "admin"),
            MockUser(2, "admin2")
        };
        _userProvider.GetUsersAsync(Arg.Any<redb.Core.Models.Users.UserSearchCriteria>()).Returns(users);
        MockRedbQuery.Setup(_redb, new List<RedbObject<UserProps>>());

        var exchange = CreateExchange("search", new Dictionary<string, object?> { ["query"] = "admin" });

        await _processor.Process(exchange);

        // Search now returns the standard PagedResult envelope shared with /users list.
        var page = exchange.Out!.Body.Should().BeAssignableTo<PagedResult<UserResponse>>().Subject;
        page.Items.Should().HaveCount(2);
        page.Items.Should().OnlyContain(r => r.Login!.Contains("admin"));
    }

    [Fact]
    public async Task Search_EmptyQuery_ReturnsValidationError()
    {
        var exchange = CreateExchange("search", new Dictionary<string, object?> { ["query"] = "" });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("validation_error");
    }

    // ── Change Password ──

    [Fact]
    public async Task ChangePassword_ValidOldPassword_Succeeds()
    {
        var coreUser = MockUser(5, "user1");
        _userProvider.GetUserByIdAsync(5).Returns(coreUser);
        _userProvider.ChangePasswordAsync(coreUser, "oldpass1", "newpass1", Arg.Any<IRedbUser?>())
            .Returns(true);
        // C7: ChangePassword now triggers SessionService.LogoutAsync — stub the relevant
        // queries so the in-memory mock returns empty lists rather than throwing NRE.
        MockRedbQuery.Setup(_redb, new List<RedbObject<SessionProps>>());
        MockRedbQuery.Setup(_redb, new List<RedbObject<AuthorizationProps>>());

        var exchange = CreateExchange("change-password", new ChangePasswordRequest
        {
            Id = 5,
            OldPassword = "oldpass1",
            NewPassword = "newpass1"
        });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((bool)body.success).Should().BeTrue();
        exchange.Properties["identity-event-type"].Should().Be("PasswordChanged");
    }

    [Fact]
    public async Task ChangePassword_RevokesAllUserSessions()
    {
        // C7: every session that was authenticated with the OLD password must be
        // invalidated when the password changes. Build two active sessions for the
        // user, change the password, and assert both ended up "revoked".
        var coreUser = MockUser(7, "user-c7");
        _userProvider.GetUserByIdAsync(7).Returns(coreUser);
        _userProvider.ChangePasswordAsync(coreUser, "old-pwd-c7", "new-pwd-c7", Arg.Any<IRedbUser?>())
            .Returns(true);

        var session1 = MockRedbQuery.CreateObject<SessionProps>(
            701, "session-701", new SessionProps { Status = "active" });
        session1.key = 7;
        var session2 = MockRedbQuery.CreateObject<SessionProps>(
            702, "session-702", new SessionProps { Status = "active" });
        session2.key = 7;
        MockRedbQuery.Setup(_redb, new List<RedbObject<SessionProps>> { session1, session2 });
        MockRedbQuery.Setup(_redb, new List<RedbObject<AuthorizationProps>>());

        var exchange = CreateExchange("change-password", new ChangePasswordRequest
        {
            Id = 7,
            OldPassword = "old-pwd-c7",
            NewPassword = "new-pwd-c7"
        });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((bool)body.success).Should().BeTrue();
        session1.Props.Status.Should().Be("revoked");
        session2.Props.Status.Should().Be("revoked");
        // The audit event should report how many sessions were revoked.
        var data = exchange.Properties["identity-event-data"]!;
        var revoked = (int)data.GetType().GetProperty("SessionsRevoked")!.GetValue(data)!;
        revoked.Should().Be(2);
    }

    [Fact]
    public async Task ChangePassword_WrongOldPassword_ReturnsError()
    {
        var coreUser = MockUser(5, "user1");
        _userProvider.GetUserByIdAsync(5).Returns(coreUser);
        _userProvider.ChangePasswordAsync(coreUser, "wrongpwd", "newpass1", Arg.Any<IRedbUser?>())
            .Returns(false);

        var exchange = CreateExchange("change-password", new ChangePasswordRequest
        {
            Id = 5,
            OldPassword = "wrongpwd",
            NewPassword = "newpass1"
        });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("invalid_password");
    }

    [Fact]
    public async Task ChangePassword_UserNotFound_ReturnsNotFound()
    {
        _userProvider.GetUserByIdAsync(999).Returns((IRedbUser?)null);

        var exchange = CreateExchange("change-password", new ChangePasswordRequest
        {
            Id = 999,
            OldPassword = "old12345",
            NewPassword = "new12345"
        });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("not_found");
    }

    // ── Input Validation ──

    [Fact]
    public async Task Create_PasswordTooShort_ReturnsValidationError()
    {
        var exchange = CreateExchange("create", new CreateUserRequest
        {
            Login = "user1",
            Password = "short"
        });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("validation_error");
        ((string)body.error_description).Should().Contain("at least");
    }

    [Fact]
    public async Task Create_InvalidLoginChars_ReturnsValidationError()
    {
        var exchange = CreateExchange("create", new CreateUserRequest
        {
            Login = "user@name!",
            Password = "P@ssw0rd!"
        });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("validation_error");
        ((string)body.error_description).Should().Contain("invalid characters");
    }

    [Fact]
    public async Task Create_InvalidEmail_ReturnsValidationError()
    {
        var exchange = CreateExchange("create", new CreateUserRequest
        {
            Login = "user1",
            Password = "P@ssw0rd!",
            Email = "not-an-email"
        });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("validation_error");
        ((string)body.error_description).Should().Contain("email");
    }

    [Fact]
    public async Task Create_InvalidPhoneNumber_ReturnsValidationError()
    {
        var exchange = CreateExchange("create", new CreateUserRequest
        {
            Login = "user1",
            Password = "P@ssw0rd!",
            PhoneNumber = "123-456"
        });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("validation_error");
        ((string)body.error_description).Should().Contain("E.164");
    }

    [Fact]
    public async Task ChangePassword_PasswordTooShort_ReturnsValidationError()
    {
        var exchange = CreateExchange("change-password", new ChangePasswordRequest
        {
            Id = 5,
            OldPassword = "oldpass1",
            NewPassword = "short"
        });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("validation_error");
        ((string)body.error_description).Should().Contain("at least");
    }

    [Fact]
    public async Task ChangePassword_SameAsOld_ReturnsValidationError()
    {
        var exchange = CreateExchange("change-password", new ChangePasswordRequest
        {
            Id = 5,
            OldPassword = "P@ssw0rd!",
            NewPassword = "P@ssw0rd!"
        });

        await _processor.Process(exchange);

        var body = (dynamic)exchange.Out!.Body!;
        ((string)body.error).Should().Be("validation_error");
        ((string)body.error_description).Should().Contain("differ");
    }
}
