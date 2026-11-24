using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using AwesomeAssertions;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// A group request that lacks a required field is the caller's mistake and is answered 400, and a
/// membership request for a group that does not exist is never a server error.
/// </summary>
[Collection("ProductionHttp")]
public class GroupRequestValidationTests
{
    private const string MissingId = "987654321012";

    private readonly ProductionHttpFixture _fx;
    private readonly ITestOutputHelper _out;

    public GroupRequestValidationTests(ProductionHttpFixture fx, ITestOutputHelper output)
    {
        _fx = fx;
        _out = output;
    }

    public static IEnumerable<object?[]> IncompleteRequests() => new[]
    {
        new object?[] { "POST", "/api/v1/identity/groups", "{}" },
        new object?[] { "POST", "/api/v1/identity/groups", null },
        new object?[] { "POST", "/api/v1/identity/groups/{group}/children", "{}" },
        new object?[] { "POST", "/api/v1/identity/groups/{group}/move", "{}" },
        new object?[] { "POST", "/api/v1/identity/groups/{group}/members", "{}" },
        new object?[] { "PUT", "/api/v1/identity/groups/{group}/members/1", "{}" },
        new object?[] { "PUT", "/api/v1/identity/groups/{group}", null },
    };

    [Theory]
    [MemberData(nameof(IncompleteRequests))]
    public async Task ARequestThatLacksARequiredField_IsAnswered400(string method, string path, string? body)
    {
        var groupId = await CreateGroupAsync();
        using var response = await SendAsync(method, path.Replace("{group}", groupId), body);
        var answer = await response.Content.ReadAsStringAsync();
        _out.WriteLine($"INCOMPLETE {method} {path} {body ?? "(no body)"} -> [{(int)response.StatusCode}] {(answer.Length > 200 ? answer[..200] : answer)}");

        ((int)response.StatusCode).Should().Be(400, answer);
    }

    [Fact]
    public async Task RemovingAMemberOfAGroupThatDoesNotExist_IsNotAServerError()
    {
        using var response = await SendAsync("DELETE", $"/api/v1/identity/groups/{MissingId}/members/1", body: null);
        var answer = await response.Content.ReadAsStringAsync();
        _out.WriteLine($"INCOMPLETE DELETE member of a missing group -> [{(int)response.StatusCode}] {answer}");

        ((int)response.StatusCode).Should().BeLessThan(500, answer);
    }

    [Theory]
    [InlineData("PUT", """{"role":"member"}""")]
    [InlineData("DELETE", null)]
    public async Task AMembershipThatDoesNotExist_IsAnswered404(string method, string? body)
    {
        // An existing group, and a user who is not one of its members.
        var groupId = await CreateGroupAsync();
        using var response = await SendAsync(method, $"/api/v1/identity/groups/{groupId}/members/987654321", body);
        var answer = await response.Content.ReadAsStringAsync();

        ((int)response.StatusCode).Should().Be(404, answer);
    }

    [Fact]
    public async Task AnExpiredMembership_CanStillBeRemoved()
    {
        // The record exists although the membership no longer counts: it must stay removable.
        var groupId = long.Parse(await CreateGroupAsync());
        const long userId = 987650001;
        await _fx.UseRedbAsync(redb => new GroupService(redb).AddMemberAsync(
            groupId, userId, "member", DateTimeOffset.UtcNow.AddDays(-1)));

        using var response = await SendAsync("DELETE", $"/api/v1/identity/groups/{groupId}/members/{userId}", body: null);
        ((int)response.StatusCode).Should().Be(200, await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task AMembershipInheritedFromTheParentGroup_IsNotARecordOfTheChild()
    {
        // The user belongs to the parent, so the membership check says yes for the child too, but
        // there is no record in the child to change: 404, not a server error.
        const long userId = 987650002;
        var parentId = long.Parse(await CreateGroupAsync());
        var childId = await _fx.UseRedbAsync(async redb =>
        {
            var groups = new GroupService(redb);
            await groups.AddMemberAsync(parentId, userId, "member");
            var child = await groups.CreateChildGroupAsync(parentId, "validation-child-" + Guid.NewGuid().ToString("N")[..12]);
            return child.Id;
        });

        using var response = await SendAsync("PUT", $"/api/v1/identity/groups/{childId}/members/{userId}", """{"role":"owner"}""");
        ((int)response.StatusCode).Should().Be(404, await response.Content.ReadAsStringAsync());
    }

    private async Task<string> CreateGroupAsync()
    {
        using var response = await SendAsync("POST", "/api/v1/identity/groups",
            JsonSerializer.Serialize(new { name = "validation-" + Guid.NewGuid().ToString("N")[..12] }));
        var answer = await response.Content.ReadAsStringAsync();
        ((int)response.StatusCode).Should().BeInRange(200, 299, answer);
        using var json = JsonDocument.Parse(answer);
        return json.RootElement.GetProperty("id").ToString();
    }

    private Task<HttpResponseMessage> SendAsync(string method, string path, string? body)
    {
        var request = new HttpRequestMessage(new HttpMethod(method), path);
        if (body is not null)
            request.Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fx.ManagementToken);
        return _fx.Http.SendAsync(request);
    }
}
