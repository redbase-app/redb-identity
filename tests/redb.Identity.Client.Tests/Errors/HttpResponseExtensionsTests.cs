using System.Net;
using System.Text;
using FluentAssertions;
using redb.Identity.Client.Internal;
using redb.Identity.Client.Tests.TestKit;
using Xunit;

namespace redb.Identity.Client.Tests.Errors;

public sealed class HttpResponseExtensionsTests
{
    [Fact]
    public async Task EnsureSuccess_DoesNothing_On_2xx()
    {
        using var resp = FakeHttpMessageHandler.BuildResponse(HttpStatusCode.OK, "{}");
        var act = () => resp.EnsureSuccessOrThrowAsync();
        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task EnsureSuccess_Throws_ApiException_On_4xx()
    {
        using var resp = FakeHttpMessageHandler.BuildResponse(HttpStatusCode.NotFound, null);
        var ex = await Assert.ThrowsAsync<ApiException>(() => resp.EnsureSuccessOrThrowAsync());
        ex.StatusCode.Should().Be(HttpStatusCode.NotFound);
        ex.ProblemDetails.Should().BeNull();
    }

    [Fact]
    public async Task EnsureSuccess_Parses_ProblemDetails_When_ProblemJson()
    {
        var body = "{\"type\":\"https://x/y\",\"title\":\"User not found\",\"status\":404,\"detail\":\"id=42\"}";
        using var resp = FakeHttpMessageHandler.BuildResponse(HttpStatusCode.NotFound, body, "application/problem+json");

        var ex = await Assert.ThrowsAsync<ApiException>(() => resp.EnsureSuccessOrThrowAsync());

        ex.StatusCode.Should().Be(HttpStatusCode.NotFound);
        ex.ProblemDetails.Should().NotBeNull();
        ex.ProblemDetails!.Title.Should().Be("User not found");
        ex.ProblemDetails!.Detail.Should().Be("id=42");
        ex.ProblemDetails!.Status.Should().Be(404);
        ex.Message.Should().Be("User not found");
        ex.RawBody.Should().Be(body);
    }

    [Fact]
    public async Task EnsureSuccess_Parses_ValidationErrors()
    {
        var body = """
        {
          "title":"One or more validation errors occurred.",
          "status":400,
          "errors":{"Email":["Required."],"Password":["TooShort.","NoDigit."]}
        }
        """;
        using var resp = FakeHttpMessageHandler.BuildResponse(HttpStatusCode.BadRequest, body, "application/problem+json");

        var ex = await Assert.ThrowsAsync<ApiException>(() => resp.EnsureSuccessOrThrowAsync());
        ex.ProblemDetails!.Errors.Should().NotBeNull();
        ex.ProblemDetails!.Errors!["Email"].Should().ContainSingle().Which.Should().Be("Required.");
        ex.ProblemDetails!.Errors!["Password"].Should().HaveCount(2);
    }

    [Fact]
    public async Task EnsureSuccess_Falls_Back_When_Body_Empty()
    {
        using var resp = FakeHttpMessageHandler.BuildResponse(HttpStatusCode.InternalServerError, null);
        var ex = await Assert.ThrowsAsync<ApiException>(() => resp.EnsureSuccessOrThrowAsync());
        ex.Message.Should().Contain("500");
        ex.ProblemDetails.Should().BeNull();
    }

    [Fact]
    public async Task EnsureSuccess_Falls_Back_When_Body_NotJson()
    {
        using var resp = new HttpResponseMessage(HttpStatusCode.BadGateway)
        {
            Content = new StringContent("<html><body>nginx 502</body></html>", Encoding.UTF8, "text/html"),
        };
        var ex = await Assert.ThrowsAsync<ApiException>(() => resp.EnsureSuccessOrThrowAsync());
        ex.ProblemDetails.Should().BeNull();
        ex.RawBody.Should().Contain("nginx");
        ex.Message.Should().Contain("502");
    }

    [Fact]
    public async Task ReadJson_Throws_ApiException_When_Body_Empty_2xx()
    {
        using var resp = new HttpResponseMessage(HttpStatusCode.OK);
        var ex = await Assert.ThrowsAsync<ApiException>(() => resp.ReadJsonAsync<Sample>());
        ex.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task ReadJson_Deserializes_On_Success()
    {
        using var resp = FakeHttpMessageHandler.BuildResponse(HttpStatusCode.OK, "{\"name\":\"Alice\",\"age\":30}");
        var s = await resp.ReadJsonAsync<Sample>();
        s.Name.Should().Be("Alice");
        s.Age.Should().Be(30);
    }

    private sealed record Sample(string Name, int Age);
}
