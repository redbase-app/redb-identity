using System.Net;
using FluentAssertions;
using redb.Identity.Client.Tests.TestKit;
using redb.Identity.Contracts.Applications;
using redb.Identity.Contracts.Common;
using Xunit;

namespace redb.Identity.Client.Tests.Endpoints;

public sealed class ApplicationsClientTests
{
    [Fact]
    public async Task ListApplications_GETs_paged_endpoint()
    {
        var paged = new PagedResult<ApplicationResponse>
        {
            Items = [new() { Id = "a1", ClientId = "c1" }],
            Total = 1, Offset = 0, Count = 25,
        };
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(paged));

        var result = await fx.Client.ListApplicationsAsync(0, 25);

        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Get);
        fx.Handler.Requests.Single().RequestUri!.PathAndQuery.Should().Be("/api/v1/identity/applications?offset=0&count=25");
        result.Items.Should().HaveCount(1);
        result.Items[0].ClientId.Should().Be("c1");
    }

    [Fact]
    public async Task GetApplication_GETs_by_id()
    {
        var app = new ApplicationResponse { Id = "abc", ClientId = "my-client" };
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(app));

        var result = await fx.Client.GetApplicationAsync("abc");

        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Get);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/applications/abc");
        result.ClientId.Should().Be("my-client");
    }

    [Fact]
    public async Task CreateApplication_POSTs_request_body()
    {
        var created = new ApplicationResponse { Id = "new", ClientId = "x" };
        var fx = new IdentityClientFixture(HttpStatusCode.Created, IdentityClientFixture.Json(created));

        var req = new CreateApplicationRequest { ClientId = "x", DisplayName = "X" };
        var result = await fx.Client.CreateApplicationAsync(req);

        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Post);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/applications");
        fx.Handler.RequestBodies[0].Should().Contain("\"clientId\":\"x\"");
        result.Id.Should().Be("new");
    }

    [Fact]
    public async Task UpdateApplication_PUTs_to_id_path()
    {
        var updated = new ApplicationResponse { Id = "abc", ClientId = "renamed" };
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(updated));

        var req = new UpdateApplicationRequest { Id = "abc", DisplayName = "renamed" };
        var result = await fx.Client.UpdateApplicationAsync("abc", req);

        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Put);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/applications/abc");
        result.ClientId.Should().Be("renamed");
    }

    [Fact]
    public async Task DeleteApplication_DELETE_returns_void_on_success()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.NoContent);

        await fx.Client.DeleteApplicationAsync("xyz");

        fx.Handler.Requests.Single().Method.Should().Be(HttpMethod.Delete);
        fx.Handler.Requests.Single().RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/applications/xyz");
    }

    [Fact]
    public async Task DeleteApplication_throws_ApiException_on_404()
    {
        var fx = new IdentityClientFixture(HttpStatusCode.NotFound, "{\"title\":\"App not found\",\"status\":404}", "application/problem+json");

        var act = () => fx.Client.DeleteApplicationAsync("nope");
        var ex = await act.Should().ThrowAsync<ApiException>();
        ex.Which.StatusCode.Should().Be(HttpStatusCode.NotFound);
        ex.Which.ProblemDetails!.Title.Should().Be("App not found");
    }

    [Fact]
    public async Task RotateApplicationSecret_POSTs_to_rotate_secret_subroute_and_returns_newSecret()
    {
        // The contract: server echoes the application back with NewSecret populated exactly once.
        var rotated = new ApplicationResponse
        {
            Id = "42",
            ClientId = "svc-a",
            ClientType = "confidential",
            NewSecret = "BASE64-PLAINTEXT-RETURNED-ONCE"
        };
        var fx = new IdentityClientFixture(HttpStatusCode.OK, IdentityClientFixture.Json(rotated));

        var result = await fx.Client.RotateApplicationSecretAsync("42");

        var req = fx.Handler.Requests.Single();
        req.Method.Should().Be(HttpMethod.Post);
        req.RequestUri!.AbsolutePath.Should().Be("/api/v1/identity/applications/42/rotate-secret");
        // Empty body: the route id alone identifies the target.
        (req.Content?.Headers.ContentLength ?? 0).Should().Be(0);
        result.NewSecret.Should().Be("BASE64-PLAINTEXT-RETURNED-ONCE");
        result.ClientId.Should().Be("svc-a");
    }

    [Fact]
    public async Task RotateApplicationSecret_throws_ApiException_on_400_for_public_client()
    {
        var fx = new IdentityClientFixture(
            HttpStatusCode.BadRequest,
            "{\"title\":\"Public clients have no client_secret to rotate.\",\"status\":400,\"type\":\"invalid_client_type\"}",
            "application/problem+json");

        var act = () => fx.Client.RotateApplicationSecretAsync("99");
        var ex = await act.Should().ThrowAsync<ApiException>();
        ex.Which.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }
}
