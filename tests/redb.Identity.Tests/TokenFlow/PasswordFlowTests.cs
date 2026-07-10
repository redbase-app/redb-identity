using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NSubstitute;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using redb.Core;
using redb.Core.Models.Contracts;
using redb.Core.Models.Entities;
using redb.Core.Providers;
using redb.Core.Query;
using redb.Identity.Core.Models;
using redb.Identity.Core.OpenIddict;
using redb.Identity.Core.Routes.Processors;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace redb.Identity.Tests.TokenFlow;

/// <summary>
/// Integration tests for the Token endpoint (password / ROPC flow).
/// Uses OpenIddict degraded mode with a mock <see cref="LoginService"/>.
/// Validates the full pipeline path: IExchange → OpenIddict → HandleTokenRequestHandler → LoginService → JWT.
/// </summary>
public class PasswordFlowTests
{
    private const string TestUsername = "testuser";
    private const string TestPassword = "Test@Password123";
    private const long TestUserId = 42;
    private static readonly Guid TestSubjectGuid = Guid.Parse("11111111-2222-3333-4444-555555555555");

    private static ServiceProvider BuildServiceProvider(
        IRedbUser? validatedUser = null,
        bool userEnabled = true,
        UserProps? oidcProps = null,
        bool simulateUserNotFound = false)
    {
        var services = new ServiceCollection();
        services.AddLogging(b => b.SetMinimumLevel(LogLevel.Warning));

        // Mock IRedbService with IUserProvider
        // simulateUserNotFound=true: ValidateUserAsync returns null for ANY input — mirrors
        // the production contract for both "user not found" and "user disabled" branches.
        var mockUser = simulateUserNotFound
            ? null
            : (validatedUser ?? CreateMockUser(TestUserId, TestUsername, userEnabled));
        var mockRedb = CreateMockRedb(mockUser, oidcProps);
        services.AddSingleton(mockRedb);

        // Register LoginService (depends on IRedbService)
        services.AddTransient<LoginService>();

        services.AddOpenIddict()
            .AddServer(options =>
            {
                options.EnableDegradedMode();
                options.SetIssuer(new Uri("https://identity.test.local/"));
                options.SetTokenEndpointUris("/connect/token");
                options.AllowPasswordFlow();

                options.AddEphemeralEncryptionKey();
                options.AddEphemeralSigningKey();
                options.DisableAccessTokenEncryption();

                options.UseRedbRoute();

                // Degraded mode: skip client validation
                options.AddEventHandler<ValidateTokenRequestContext>(builder =>
                    builder
                        .UseInlineHandler(context => default)
                        .SetOrder(int.MaxValue - 100_000)
                        .Build());
            });

        return services.BuildServiceProvider();
    }

    private static IRedbUser CreateMockUser(long id, string login, bool enabled = true)
    {
        var user = Substitute.For<IRedbUser>();
        user.Id.Returns(id);
        user.Login.Returns(login);
        user.Enabled.Returns(enabled);
        user.Email.Returns("testuser@example.com");
        user.Phone.Returns("+1234567890");
        return user;
    }

    private static IRedbService CreateMockRedb(IRedbUser? validatedUser, UserProps? oidcProps)
    {
        var redb = Substitute.For<IRedbService>();
        var userProvider = Substitute.For<IUserProvider>();

        // ValidateUserAsync returns user only for correct credentials
        userProvider.ValidateUserAsync(TestUsername, TestPassword)
            .Returns(Task.FromResult(validatedUser));
        userProvider.ValidateUserAsync(Arg.Is<string>(u => u != TestUsername), Arg.Any<string>())
            .Returns(Task.FromResult<IRedbUser?>(null));
        userProvider.ValidateUserAsync(TestUsername, Arg.Is<string>(p => p != TestPassword))
            .Returns(Task.FromResult<IRedbUser?>(null));

        redb.UserProvider.Returns(userProvider);

        // Mock Query<UserProps> for OIDC props lookup
        var queryable = Substitute.For<IRedbQueryable<UserProps>>();
        queryable.WhereRedb(Arg.Any<System.Linq.Expressions.Expression<Func<IRedbObject, bool>>>())
            .Returns(queryable);

        if (oidcProps is not null)
        {
            var obj = new RedbObject<UserProps>(oidcProps)
            {
                key = validatedUser?.Id ?? 0,
                value_guid = TestSubjectGuid
            };
            queryable.FirstOrDefaultAsync()
                .Returns(Task.FromResult<RedbObject<UserProps>?>(obj));
        }
        else if (validatedUser is not null)
        {
            // The token pipeline requires a non-empty subject GUID even when the test
            // doesn't care about OIDC profile claims. Seed a minimal UserProps so
            // IdentityPrincipalBuilder.Build receives SubjectGuid = TestSubjectGuid.
            var obj = new RedbObject<UserProps>(new UserProps())
            {
                key = validatedUser.Id,
                value_guid = TestSubjectGuid
            };
            queryable.FirstOrDefaultAsync()
                .Returns(Task.FromResult<RedbObject<UserProps>?>(obj));
        }
        else
        {
            queryable.FirstOrDefaultAsync()
                .Returns(Task.FromResult<RedbObject<UserProps>?>(null));
        }
        redb.Query<UserProps>().Returns(queryable);

        return redb;
    }

    // ── Happy path ──

    [Fact]
    public async Task ValidCredentials_ReturnsAccessToken()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = TestUsername,
            ["password"] = TestPassword,
            ["client_id"] = "test-client"
        };

        var processor = new TokenEndpointProcessor(handler);
        await processor.Process(exchange);

        exchange.Out.Should().NotBeNull();
        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body.Should().ContainKey("access_token");
        body["access_token"]!.ToString().Should().NotBeEmpty();
        body["token_type"].Should().Be("Bearer");
        body["expires_in"].Should().NotBeNull();
        body.Should().NotContainKey("error");
    }

    [Fact]
    public async Task ValidCredentials_JwtContainsUserClaims()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = TestUsername,
            ["password"] = TestPassword,
            ["client_id"] = "test-client"
        };

        var processor = new TokenEndpointProcessor(handler);
        await processor.Process(exchange);

        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body.Should().NotContainKey("error",
            because: $"should succeed, got: {(body.ContainsKey("error_description") ? body["error_description"] : "n/a")}");
        var jwt = body["access_token"]!.ToString()!;
        var parts = jwt.Split('.');
        parts.Should().HaveCount(3, "access_token should be a JWT");

        var payloadJson = Encoding.UTF8.GetString(
            Convert.FromBase64String(PadBase64(parts[1])));
        var claims = JsonSerializer.Deserialize<JsonElement>(payloadJson);

        claims.TryGetProperty("sub", out var sub).Should().BeTrue("JWT should contain sub");
        sub.GetString().Should().Be(TestSubjectGuid.ToString("D"),
            because: "the public sub claim is the per-user GUID stored on UserProps.value_guid");

        claims.TryGetProperty("redb:user_id", out var internalUid).Should().BeTrue(
            "access token must mirror the bigint _users._id into the internal claim");
        internalUid.GetString().Should().Be(TestUserId.ToString());

        claims.TryGetProperty("name", out var name).Should().BeTrue("JWT should contain name");
        name.GetString().Should().Be(TestUsername);
    }

    [Fact]
    public async Task ValidCredentials_SetsEventMetadata()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = TestUsername,
            ["password"] = TestPassword,
            ["client_id"] = "test-client"
        };

        var processor = new TokenEndpointProcessor(handler);
        await processor.Process(exchange);

        exchange.Properties.Should().ContainKey("identity-event-type");
        exchange.Properties["identity-event-type"].Should().Be("TokenIssued");
        exchange.Properties.Should().ContainKey("identity-event-data");
    }

    // ── Error cases ──

    [Fact]
    public async Task InvalidPassword_ReturnsAccessDenied()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = TestUsername,
            ["password"] = "wrong-password",
            ["client_id"] = "test-client"
        };

        var processor = new TokenEndpointProcessor(handler);
        await processor.Process(exchange);

        exchange.Out.Should().NotBeNull();
        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body.Should().ContainKey("error");
        body["error"].Should().Be("access_denied");
    }

    [Fact]
    public async Task UnknownUsername_ReturnsAccessDenied()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = "unknown-user",
            ["password"] = "any-password",
            ["client_id"] = "test-client"
        };

        var processor = new TokenEndpointProcessor(handler);
        await processor.Process(exchange);

        exchange.Out.Should().NotBeNull();
        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body.Should().ContainKey("error");
        body["error"].Should().Be("access_denied");
    }

    [Fact]
    public async Task DisabledUser_ReturnsAccessDenied()
    {
        // C14: contract of UserProvider.ValidateUserAsync — returns null for disabled users
        // (so the LoginService cannot distinguish "wrong password" from "disabled" via
        // result shape or timing). Use simulateUserNotFound=true to mirror that path.
        await using var sp = BuildServiceProvider(simulateUserNotFound: true);
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = TestUsername,
            ["password"] = TestPassword,
            ["client_id"] = "test-client"
        };

        var processor = new TokenEndpointProcessor(handler);
        await processor.Process(exchange);

        exchange.Out.Should().NotBeNull();
        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body.Should().ContainKey("error");
        body["error"].Should().Be("access_denied");
        // C14 / SEC-A20: error_description must be the unified "Invalid credentials." —
        // never reveal "user disabled" vs "wrong password" to the caller.
        body["error_description"].Should().Be("Invalid credentials.");
    }

    [Fact]
    public async Task MissingUsername_ReturnsError()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["password"] = TestPassword,
            ["client_id"] = "test-client"
        };

        var processor = new TokenEndpointProcessor(handler);
        await processor.Process(exchange);

        exchange.Out.Should().NotBeNull();
        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body.Should().ContainKey("error");
        // RFC 6749 §4.3.2: username is REQUIRED — OpenIddict rejects with invalid_request
        body["error"].Should().Be("invalid_request");
    }

    [Fact]
    public async Task MissingPassword_ReturnsError()
    {
        await using var sp = BuildServiceProvider();
        using var scope = sp.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RedbRouteOpenIddictServerHandler>();

        var exchange = new TestExchange();
        exchange.In.Body = new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = TestUsername,
            ["client_id"] = "test-client"
        };

        var processor = new TokenEndpointProcessor(handler);
        await processor.Process(exchange);

        exchange.Out.Should().NotBeNull();
        var body = exchange.Out!.Body.Should().BeOfType<Dictionary<string, object?>>().Subject;
        body.Should().ContainKey("error");
        // RFC 6749 §4.3.2: password is REQUIRED — OpenIddict rejects with invalid_request
        body["error"].Should().Be("invalid_request");
    }

    // ── Helpers ──

    private static string PadBase64(string base64)
    {
        switch (base64.Length % 4)
        {
            case 2: return base64 + "==";
            case 3: return base64 + "=";
            default: return base64;
        }
    }
}
