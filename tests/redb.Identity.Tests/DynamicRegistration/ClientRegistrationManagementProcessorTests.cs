using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;
using OpenIddict.Abstractions;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Contracts.Registration;
using redb.Identity.Core.Models;
using redb.Identity.Contracts.Routes;
using redb.Identity.Core.Routes.Processors;
using redb.Identity.Tests.Infrastructure;
using redb.Route.Abstractions;
using Xunit;

namespace redb.Identity.Tests.DynamicRegistration;

/// <summary>
/// Z2 (RFC 7592): Unit tests for <see cref="ClientRegistrationManagementProcessor"/>.
/// Exercises read/update/delete via <c>operation</c> header plus RFC 7592 §3 security:
/// missing/wrong/non-DCR RAT → 401; unknown client → 404; RAT verified in fixed time;
/// client_secret NEVER echoed back on read.
/// </summary>
public class ClientRegistrationManagementProcessorTests
{
    private const string Token = "test-registration-access-token-abcdef1234567890";

    private readonly IOpenIddictApplicationManager _manager = Substitute.For<IOpenIddictApplicationManager>();
    private readonly IRedbService _redb = Substitute.For<IRedbService>();

    private static string Sha256Hex(string s)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(s));
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (var b in bytes) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }

    private ClientRegistrationManagementProcessor CreateProcessor()
    {
        var services = new ServiceCollection();
        services.AddSingleton(_manager);
        services.AddSingleton(_redb);
        var sp = services.BuildServiceProvider();

        var ctx = Substitute.For<IRouteContext>();
        ctx.GetServiceProvider().Returns(sp);
        // NSubstitute auto-mocks interface return types — pin GetFromRegistry to null so
        // GetIdentityService falls through to the host SP instead of an empty auto-mocked scope.
        ctx.GetFromRegistry<IServiceScopeFactory>(Arg.Any<string>()).Returns((IServiceScopeFactory?)null);
        ctx.GetService<IRedbService>().Returns(_redb);
        return new ClientRegistrationManagementProcessor(ctx);
    }

    private static TestExchange MakeExchange(string operation, string? clientId, string? bearer = Token)
    {
        var ex = new TestExchange();
        ex.In.Headers["operation"] = operation;
        if (clientId is not null) ex.In.Headers["client_id"] = clientId;
        if (bearer is not null) ex.In.Headers["access_token"] = bearer;
        return ex;
    }

    private RedbObject<ApplicationProps> ApplicationWithStoredHash(
        string clientId = "client-123",
        string? redirectUri = "https://app.example.com/cb",
        bool hasDcrHash = true)
    {
        var app = new RedbObject<ApplicationProps>
        {
            name = "My App",
            Props = new ApplicationProps
            {
                ClientId = clientId,
                ClientType = "public",
                RedirectUris = redirectUri is null ? null : [redirectUri],
                ApplicationType = "web",
                RegistrationAccessTokenHash = hasDcrHash ? Sha256Hex(Token) : null
            }
        };
        _manager.FindByClientIdAsync(clientId, Arg.Any<CancellationToken>())
            .Returns(new ValueTask<object?>(app));
        return app;
    }

    // ── Auth failures ──

    [Fact]
    public async Task Missing_ClientId_Returns_400()
    {
        var proc = CreateProcessor();
        var ex = MakeExchange("read", clientId: null);

        await proc.Process(ex);

        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(400);
    }

    [Fact]
    public async Task Missing_Bearer_Returns_401()
    {
        var proc = CreateProcessor();
        var ex = MakeExchange("read", "client-123", bearer: null);

        await proc.Process(ex);

        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(401);
        var body = (IDictionary<string, object?>)ex.Out.Body!;
        body["error"]!.ToString().Should().Be("invalid_token");
    }

    [Fact]
    public async Task Unknown_Client_Returns_404()
    {
        _manager.FindByClientIdAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new ValueTask<object?>((object?)null));
        var proc = CreateProcessor();
        var ex = MakeExchange("read", "does-not-exist");

        await proc.Process(ex);

        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(404);
        var body = (IDictionary<string, object?>)ex.Out.Body!;
        body["error"]!.ToString().Should().Be("invalid_client_id");
    }

    [Fact]
    public async Task Client_Without_Dcr_Hash_Returns_401()
    {
        ApplicationWithStoredHash(hasDcrHash: false);
        var proc = CreateProcessor();
        var ex = MakeExchange("read", "client-123");

        await proc.Process(ex);

        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(401);
        var body = (IDictionary<string, object?>)ex.Out.Body!;
        body["error"]!.ToString().Should().Be("invalid_token");
        body["error_description"]!.ToString().Should().Contain("not eligible");
    }

    [Fact]
    public async Task Wrong_Bearer_Returns_401()
    {
        ApplicationWithStoredHash();
        var proc = CreateProcessor();
        var ex = MakeExchange("read", "client-123", bearer: "not-the-real-token");

        await proc.Process(ex);

        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(401);
        var body = (IDictionary<string, object?>)ex.Out.Body!;
        body["error"]!.ToString().Should().Be("invalid_token");
    }

    [Fact]
    public async Task Authorization_Header_Accepted_As_Fallback()
    {
        ApplicationWithStoredHash();
        var proc = CreateProcessor();
        var ex = MakeExchange("read", "client-123", bearer: null);
        ex.In.Headers["Authorization"] = $"Bearer {Token}";

        await proc.Process(ex);

        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(200);
    }

    // ── Read ──

    [Fact]
    public async Task Read_Returns_Metadata_Without_Secrets()
    {
        var app = ApplicationWithStoredHash();
        app.Props.ClientSecret = "super-secret-should-not-leak";
        var proc = CreateProcessor();
        var ex = MakeExchange("read", "client-123");

        await proc.Process(ex);

        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(200);
        var body = (IDictionary<string, object?>)ex.Out.Body!;
        body["client_id"]!.ToString().Should().Be("client-123");
        body["client_name"]!.ToString().Should().Be("My App");
        body.ContainsKey("client_secret").Should().BeFalse("RFC 7592 §2.3 — client_secret MUST NOT be returned on GET");
        body.ContainsKey("registration_access_token").Should().BeFalse("RAT is one-shot at creation — never echoed");
        var redirs = (System.Collections.Generic.IEnumerable<object?>)((System.Text.Json.JsonElement)body["redirect_uris"]!).EnumerateArray().Cast<object?>();
        redirs.Select(o => o!.ToString()).Should().ContainSingle().Which.Should().Be("https://app.example.com/cb");
    }

    // ── Update ──

    [Fact]
    public async Task Update_Persists_Changes_And_Returns_Updated_Metadata()
    {
        var app = ApplicationWithStoredHash();
        RedbObject<ApplicationProps>? savedApp = null;
        _redb.SaveAsync(Arg.Do<RedbObject<ApplicationProps>>(r => savedApp = r))
            .Returns(Task.FromResult(1L));

        var proc = CreateProcessor();
        var ex = MakeExchange("update", "client-123");
        ex.In.Body = new DynamicRegistrationRequest
        {
            ClientName = "Renamed App",
            RedirectUris = ["https://new.example.com/cb"]
        };

        await proc.Process(ex);

        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(200);
        savedApp.Should().BeSameAs(app);
        savedApp!.name.Should().Be("Renamed App");
        savedApp.Props.RedirectUris.Should().BeEquivalentTo(["https://new.example.com/cb"]);

        var body = (IDictionary<string, object?>)ex.Out.Body!;
        body["client_name"]!.ToString().Should().Be("Renamed App");
        ((System.Text.Json.JsonElement)body["redirect_uris"]!).EnumerateArray()
            .Select(e => e.GetString()).Should().BeEquivalentTo(["https://new.example.com/cb"]);

        ex.Properties["identity-event-type"].Should().Be(IdentityAuditEventIds.ClientUpdated);
    }

    [Fact]
    public async Task Update_Accepts_Json_String_Body()
    {
        ApplicationWithStoredHash();
        _redb.SaveAsync(Arg.Any<RedbObject<ApplicationProps>>()).Returns(Task.FromResult(1L));

        var proc = CreateProcessor();
        var ex = MakeExchange("update", "client-123");
        ex.In.Body = """{"client_name":"From Json","redirect_uris":["https://json.example.com/cb"]}""";

        await proc.Process(ex);

        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(200);
        var body = (IDictionary<string, object?>)ex.Out.Body!;
        body["client_name"]!.ToString().Should().Be("From Json");
    }

    [Fact]
    public async Task Update_With_Invalid_Body_Returns_400()
    {
        ApplicationWithStoredHash();
        var proc = CreateProcessor();
        var ex = MakeExchange("update", "client-123");
        ex.In.Body = 42; // unsupported type

        await proc.Process(ex);

        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(400);
        var body = (IDictionary<string, object?>)ex.Out.Body!;
        body["error"]!.ToString().Should().Be("invalid_client_metadata");
    }

    // ── Delete ──

    [Fact]
    public async Task Delete_Calls_Manager_DeleteAsync_And_Returns_204()
    {
        var app = ApplicationWithStoredHash();
        var proc = CreateProcessor();
        var ex = MakeExchange("delete", "client-123");

        await proc.Process(ex);

        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(204);
        await _manager.Received(1).DeleteAsync(app, Arg.Any<CancellationToken>());
        ex.Properties["identity-event-type"].Should().Be(IdentityAuditEventIds.ClientDeleted);
    }

    // ── Unknown operation ──

    [Fact]
    public async Task Unknown_Operation_Returns_400()
    {
        ApplicationWithStoredHash();
        var proc = CreateProcessor();
        var ex = MakeExchange("explode", "client-123");

        await proc.Process(ex);

        ex.Out!.Headers["redbHttp.ResponseCode"].Should().Be(400);
        var body = (IDictionary<string, object?>)ex.Out.Body!;
        body["error"]!.ToString().Should().Be("invalid_request");
    }
}
