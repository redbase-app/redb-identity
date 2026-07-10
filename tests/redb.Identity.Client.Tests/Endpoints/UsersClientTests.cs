using System.Net;
using FluentAssertions;
using redb.Identity.Client.Tests.TestKit;
using redb.Identity.Contracts.Common;
using redb.Identity.Contracts.Users;
using Xunit;

namespace redb.Identity.Client.Tests.Endpoints;

public sealed class UsersClientTests
{
    [Fact]
    public async Task ListUsers_GETs_paged()
    {
        var paged = new PagedResult<UserResponse>
        {
            Items = [new() { Id = 1, Login = "alice" }],
            Total = 1, Offset = 0, Count = 25,
        };
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(paged));
        var result = await fx.Client.ListUsersAsync();
        fx.Handler.Requests.Single().RequestUri!.PathAndQuery.Should().Be("/api/v1/identity/users?offset=0&count=25");
        result.Items[0].Login.Should().Be("alice");
    }

    [Fact]
    public async Task GetUser_GET_by_login_or_id()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(new UserResponse { Id = 1, Login = "alice" }));
        await fx.Client.GetUserAsync("alice");
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/users/alice");
    }

    [Fact]
    public async Task CreateUser_POST_with_body()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.Created, IdentityClientFixture.Json(new UserResponse { Id = 42, Login = "bob" }));
        var result = await fx.Client.CreateUserAsync(new CreateUserRequest { Login = "bob", Password = "P@ss" });
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Post);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/users");
        fx.Handler.RequestBodies[0].Should().Contain("\"login\":\"bob\"");
        result.Id.Should().Be(42);
    }

    [Fact]
    public async Task UpdateUser_PUT_to_numeric_id()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(new UserResponse { Id = 5, Login = "x", DisplayName = "X" }));
        await fx.Client.UpdateUserAsync(5, new UpdateUserRequest { Id = 5, DisplayName = "X" });
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Put);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/users/5");
    }

    [Fact]
    public async Task DeleteUser_DELETE()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.NoContent);
        await fx.Client.DeleteUserAsync("alice");
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Delete);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/users/alice");
    }

    [Fact]
    public async Task ChangeUserPassword_POSTs_subroute()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "{\"success\":true}");
        await fx.Client.ChangeUserPasswordAsync(7, new ChangePasswordRequest { Id = 7, OldPassword = "old", NewPassword = "new" });
        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Post);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/users/7/change-password");
    }

    [Fact]
    public async Task SearchUsers_GETs_with_query()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.OK, "[{\"id\":1,\"login\":\"alice\"}]");
        var result = await fx.Client.SearchUsersAsync("ali");
        fx.Handler.Requests.Single().RequestUri!.PathAndQuery.Should().Be("/api/v1/identity/users/search?query=ali");
        result.Should().ContainSingle().Which.Login.Should().Be("alice");
    }
}
