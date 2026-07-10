using System.Net;
using FluentAssertions;
using Microsoft.Extensions.Options;
using redb.Identity.Client.Auth;
using redb.Identity.Client.Tests.TestKit;
using Xunit;

namespace redb.Identity.Client.Tests.Auth;

public sealed class BearerTokenHandlerTests
{
    [Fact]
    public async Task Adds_Authorization_Header_When_Token_Available()
    {
        var fake = new FakeHttpMessageHandler(HttpStatusCode.OK, "{}");
        var handler = new BearerTokenHandler(new StaticTokenProvider("abc.def.ghi"))
        {
            InnerHandler = fake
        };
        var http = new HttpClient(handler) { BaseAddress = new Uri("https://x.test/") };

        var resp = await http.GetAsync("/api/users");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);

        fake.Requests.Should().ContainSingle();
        fake.Requests[0].Headers.Authorization.Should().NotBeNull();
        fake.Requests[0].Headers.Authorization!.Scheme.Should().Be("Bearer");
        fake.Requests[0].Headers.Authorization!.Parameter.Should().Be("abc.def.ghi");
    }

    [Fact]
    public async Task Does_Nothing_When_Token_Is_Null()
    {
        var fake = new FakeHttpMessageHandler(HttpStatusCode.OK, "{}");
        var handler = new BearerTokenHandler(new StaticTokenProvider(null))
        {
            InnerHandler = fake
        };
        var http = new HttpClient(handler) { BaseAddress = new Uri("https://x.test/") };

        await http.GetAsync("/api/users");

        fake.Requests[0].Headers.Authorization.Should().BeNull();
    }

    [Fact]
    public async Task Does_Nothing_When_Token_Is_Empty()
    {
        var fake = new FakeHttpMessageHandler(HttpStatusCode.OK, "{}");
        var handler = new BearerTokenHandler(new StaticTokenProvider(""))
        {
            InnerHandler = fake
        };
        var http = new HttpClient(handler) { BaseAddress = new Uri("https://x.test/") };

        await http.GetAsync("/api/users");

        fake.Requests[0].Headers.Authorization.Should().BeNull();
    }

    private sealed class StaticTokenProvider : IAccessTokenProvider
    {
        private readonly string? _token;
        public StaticTokenProvider(string? token) => _token = token;
        public Task<string?> GetAccessTokenAsync(CancellationToken ct = default) => Task.FromResult(_token);
    }
}

public sealed class ClientCredentialsAccessTokenProviderTests
{
    [Fact]
    public async Task Throws_When_No_ClientCredentials_Configured()
    {
        var fake = new FakeHttpMessageHandler(HttpStatusCode.OK, "{}");
        var http = new HttpClient(fake);
        var opts = Options.Create(new IdentityClientOptions { BaseUrl = new Uri("https://id.test/") });
        var provider = new ClientCredentialsAccessTokenProvider(http, opts);

        var act = () => provider.GetAccessTokenAsync();
        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task Caches_Token_Until_Expiry()
    {
        var calls = 0;
        var fake = new FakeHttpMessageHandler(_ =>
        {
            calls++;
            return Task.FromResult(FakeHttpMessageHandler.BuildResponse(
                HttpStatusCode.OK,
                "{\"access_token\":\"tk-1\",\"token_type\":\"Bearer\",\"expires_in\":3600}"));
        });
        var http = new HttpClient(fake);
        var opts = Options.Create(new IdentityClientOptions
        {
            BaseUrl = new Uri("https://id.test/"),
            ClientId = "cli",
            ClientSecret = "sec",
            Scopes = ["identity.admin"],
        });
        using var provider = new ClientCredentialsAccessTokenProvider(http, opts);

        var t1 = await provider.GetAccessTokenAsync();
        var t2 = await provider.GetAccessTokenAsync();
        var t3 = await provider.GetAccessTokenAsync();

        t1.Should().Be("tk-1");
        t2.Should().Be("tk-1");
        t3.Should().Be("tk-1");
        calls.Should().Be(1);
    }

    [Fact]
    public async Task Posts_Form_With_grant_type_client_credentials()
    {
        var fake = new FakeHttpMessageHandler(HttpStatusCode.OK,
            "{\"access_token\":\"tk-2\",\"expires_in\":3600}");
        var http = new HttpClient(fake);
        var opts = Options.Create(new IdentityClientOptions
        {
            BaseUrl = new Uri("https://id.test/"),
            ClientId = "my-client",
            ClientSecret = "shh",
            Scopes = ["identity.admin", "scim"],
        });
        using var provider = new ClientCredentialsAccessTokenProvider(http, opts);

        await provider.GetAccessTokenAsync();

        fake.Requests.Should().ContainSingle();
        fake.Requests[0].Method.Should().Be(HttpMethod.Post);
        fake.Requests[0].RequestUri!.AbsolutePath.Should().Be("/connect/token");
        fake.RequestBodies[0].Should().Contain("grant_type=client_credentials");
        fake.RequestBodies[0].Should().Contain("client_id=my-client");
        fake.RequestBodies[0].Should().Contain("client_secret=shh");
        // form-encoded space — '+' or '%20'
        (fake.RequestBodies[0]!.Contains("scope=identity.admin+scim")
            || fake.RequestBodies[0]!.Contains("scope=identity.admin%20scim"))
            .Should().BeTrue();
    }
}
