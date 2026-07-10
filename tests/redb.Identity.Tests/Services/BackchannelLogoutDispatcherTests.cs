using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using OpenIddict.Server;
using redb.Core;
using redb.Core.Models.Contracts;
using redb.Core.Models.Entities;
using redb.Core.Query;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Services;

/// <summary>
/// Unit tests for <see cref="BackchannelLogoutDispatcher"/> — verifies that:
/// only RPs with <c>BackchannelLogoutUri</c> set receive logout_token POSTs;
/// the POST body is form-urlencoded with a valid signed JWT;
/// downstream HTTP failures don't break the logout flow.
/// </summary>
public sealed class BackchannelLogoutDispatcherTests
{
    private static (BackchannelLogoutDispatcher dispatcher, RecordingHandler handler, IRedbService redb, List<RedbObject<ApplicationProps>> apps)
        CreateDispatcher(SecurityKey? customKey = null)
    {
        var rsa = RSA.Create(2048);
        var key = customKey ?? new RsaSecurityKey(rsa.ExportParameters(true)) { KeyId = "test-rsa" };
        var creds = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);
        var serverOptions = new OpenIddictServerOptions { Issuer = new Uri("https://idp.example.com") };
        serverOptions.SigningCredentials.Add(creds);
        var monitor = Substitute.For<IOptionsMonitor<OpenIddictServerOptions>>();
        monitor.CurrentValue.Returns(serverOptions);
        var tokenBuilder = new LogoutTokenBuilder(monitor);

        var handler = new RecordingHandler();
        var httpClient = new HttpClient(handler);
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient(Arg.Any<string>()).Returns(httpClient);

        var dispatcher = new BackchannelLogoutDispatcher(factory, tokenBuilder);
        var redb = Substitute.For<IRedbService>();

        // Stub the batched Query<ApplicationProps>().WhereInRedb(...).ToListAsync() pipeline.
        // Tests register apps via StubApp which appends them to this shared list; the query
        // stub then returns the entire list (the dispatcher already filters on its own side).
        var apps = new List<RedbObject<ApplicationProps>>();
        var queryable = Substitute.For<IRedbQueryable<ApplicationProps>>();
        queryable.WhereInRedb(Arg.Any<System.Linq.Expressions.Expression<Func<IRedbObject, long>>>(),
                              Arg.Any<IEnumerable<long>>())
                 .Returns(queryable);
        queryable.ToListAsync().Returns(_ => apps.ToList());
        redb.Query<ApplicationProps>().Returns(queryable);
        return (dispatcher, handler, redb, apps);
    }

    private static void StubApp(List<RedbObject<ApplicationProps>> apps, long id, string clientId,
        string? backchannelUri, bool sessionRequired = false)
    {
        apps.Add(new RedbObject<ApplicationProps>
        {
            Id = id,
            Name = "App " + id,
            value_string = clientId,
            Props = new ApplicationProps
            {
                ClientId = clientId,
                BackchannelLogoutUri = backchannelUri,
                BackchannelLogoutSessionRequired = sessionRequired
            }
        });
    }

    [Fact]
    public async Task Dispatch_PostsLogoutToken_ToConfiguredRPs()
    {
        var (dispatcher, handler, redb, apps) = CreateDispatcher();
        StubApp(apps, 100, "client-a", "https://rp-a.example.com/logout");
        StubApp(apps, 101, "client-b", "https://rp-b.example.com/logout");

        var delivered = await dispatcher.DispatchAsync(redb, userId: 42, sessionId: 0,
            new[] { 100L, 101L });

        delivered.Should().Be(2);
        handler.Requests.Should().HaveCount(2);
        handler.Requests.Select(r => r.RequestUri!.ToString()).Should().BeEquivalentTo(new[]
        {
            "https://rp-a.example.com/logout",
            "https://rp-b.example.com/logout"
        });
    }

    [Fact]
    public async Task Dispatch_SkipsRPs_WithoutBackchannelLogoutUri()
    {
        var (dispatcher, handler, redb, apps) = CreateDispatcher();
        StubApp(apps, 200, "client-c", backchannelUri: null);
        StubApp(apps, 201, "client-d", "https://rp-d.example.com/logout");

        var delivered = await dispatcher.DispatchAsync(redb, userId: 1, sessionId: 0,
            new[] { 200L, 201L });

        delivered.Should().Be(1);
        handler.Requests.Should().ContainSingle()
            .Which.RequestUri!.ToString().Should().Be("https://rp-d.example.com/logout");
    }

    [Fact]
    public async Task Dispatch_SendsValidLogoutToken_AsFormUrlEncoded()
    {
        var (dispatcher, handler, redb, apps) = CreateDispatcher();
        StubApp(apps, 300, "client-e", "https://rp-e.example.com/logout", sessionRequired: true);

        await dispatcher.DispatchAsync(redb, userId: 99, sessionId: 555, new[] { 300L });

        var req = handler.Requests.Single();
        req.Method.Should().Be(HttpMethod.Post);
        req.Content!.Headers.ContentType!.MediaType.Should().Be("application/x-www-form-urlencoded");
        var body = handler.RequestBodies.Single();
        body.Should().StartWith("logout_token=");

        var token = System.Web.HttpUtility.ParseQueryString(body)["logout_token"];
        token.Should().NotBeNullOrEmpty();

        var jwt = new JwtSecurityTokenHandler { MapInboundClaims = false }.ReadJwtToken(token);
        jwt.Audiences.Should().ContainSingle().Which.Should().Be("client-e");
        jwt.Payload["sub"].Should().Be("99");
        jwt.Payload["sid"].Should().Be("555"); // included because sessionRequired=true and sessionId>0
    }

    [Fact]
    public async Task Dispatch_OmitsSid_WhenSessionRequiredFalse()
    {
        var (dispatcher, handler, redb, apps) = CreateDispatcher();
        StubApp(apps, 400, "client-f", "https://rp-f.example.com/logout", sessionRequired: false);

        await dispatcher.DispatchAsync(redb, userId: 1, sessionId: 999, new[] { 400L });

        var body = handler.RequestBodies.Single();
        var token = System.Web.HttpUtility.ParseQueryString(body)["logout_token"];
        var jwt = new JwtSecurityTokenHandler { MapInboundClaims = false }.ReadJwtToken(token);
        jwt.Payload.ContainsKey("sid").Should().BeFalse();
    }

    [Fact]
    public async Task Dispatch_FailedDelivery_DoesNotThrow_AndReportsZeroDelivered()
    {
        var (dispatcher, handler, redb, apps) = CreateDispatcher();
        handler.NextResponseStatus = HttpStatusCode.ServiceUnavailable;
        StubApp(apps, 500, "client-g", "https://rp-down.example.com/logout");

        var delivered = await dispatcher.DispatchAsync(redb, userId: 7, sessionId: 0, new[] { 500L });

        delivered.Should().Be(0);
        handler.Requests.Should().HaveCount(1); // attempt was made
    }

    [Fact]
    public async Task Dispatch_NoApplications_ReturnsZero_NoHttpCalls()
    {
        var (dispatcher, handler, redb, apps) = CreateDispatcher();

        var delivered = await dispatcher.DispatchAsync(redb, 1, 0, Array.Empty<long>());

        delivered.Should().Be(0);
        handler.Requests.Should().BeEmpty();
    }

    /// <summary>
    /// Captures every HTTP request and replies with a configurable status (200 by default).
    /// </summary>
    private sealed class RecordingHandler : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = new();
        public List<string> RequestBodies { get; } = new();
        public HttpStatusCode NextResponseStatus { get; set; } = HttpStatusCode.OK;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // Read body NOW because the dispatcher's `using var content` will dispose it
            // before the test can reach it.
            var body = request.Content is null
                ? string.Empty
                : await request.Content.ReadAsStringAsync(cancellationToken);

            Requests.Add(request);
            RequestBodies.Add(body);
            return new HttpResponseMessage(NextResponseStatus);
        }
    }
}
