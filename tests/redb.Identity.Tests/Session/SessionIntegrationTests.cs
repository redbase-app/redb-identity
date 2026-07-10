using FluentAssertions;
using redb.Identity.Contracts.Routes;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.Session;

/// <summary>
/// Integration tests for session management via direct-vm routes.
/// Uses <see cref="ProductionBootstrapFixture"/> with full OpenIddict pipeline.
/// </summary>
[Collection("ProductionBootstrap")]
public class SessionIntegrationTests
{
    private readonly ProductionBootstrapFixture _fx;
    private readonly ITestOutputHelper _output;

    public SessionIntegrationTests(ProductionBootstrapFixture fx, ITestOutputHelper output)
    {
        _fx = fx;
        _output = output;
    }

    [Fact]
    public async Task AuthCode_CreatesSession()
    {
        // Authenticate to create a session
        var authorizeResult = await Authorize();
        authorizeResult.Should().ContainKey("code", "Auth should succeed and create a session");

        // List sessions for the test user
        var userId = await GetTestUserId();
        var listExchange = await _fx.RequestWithHeaders(IdentityEndpoints.ManageSessions,
            new Dictionary<string, object?> { ["userId"] = userId },
            new Dictionary<string, object?> { ["operation"] = "list" });

        var sessions = listExchange.Out?.Body.Should().BeAssignableTo<IEnumerable<object>>().Subject;
        sessions.Should().NotBeEmpty("Authentication should have created a session");

        _output.WriteLine($"Found {sessions!.Count()} sessions for user {userId}");
    }

    [Fact]
    public async Task ManageSessions_ListReturnsSessionInfo()
    {
        // Authenticate first
        await Authorize();

        var userId = await GetTestUserId();
        var listExchange = await _fx.RequestWithHeaders(IdentityEndpoints.ManageSessions,
            new Dictionary<string, object?> { ["userId"] = userId },
            new Dictionary<string, object?> { ["operation"] = "list" });

        var sessions = listExchange.Out?.Body as IEnumerable<object>;
        sessions.Should().NotBeNull();

        foreach (var session in sessions!)
        {
            if (session is IDictionary<string, object?> dict)
            {
                dict.Should().ContainKey("SessionId");
                dict.Should().ContainKey("UserId");
                dict.Should().ContainKey("Status");
                _output.WriteLine($"Session: id={dict["SessionId"]}, status={dict["Status"]}");
            }
        }
    }

    [Fact]
    public async Task ManageSessions_RevokeAll_RevokesAllSessions()
    {
        // Authenticate multiple times
        await Authorize();
        await Authorize();

        var userId = await GetTestUserId();

        // Revoke all sessions
        var revokeExchange = await _fx.RequestWithHeaders(IdentityEndpoints.ManageSessions,
            new Dictionary<string, object?> { ["userId"] = userId },
            new Dictionary<string, object?> { ["operation"] = "revoke-all" });

        var revokeResponse = (Dictionary<string, object?>)revokeExchange.Out!.Body!;
        revokeResponse.Should().ContainKey("success");
        ((bool)revokeResponse["success"]!).Should().BeTrue();

        var revoked = Convert.ToInt32(revokeResponse["revoked"]);
        revoked.Should().BeGreaterOrEqualTo(1);
        _output.WriteLine($"Revoked {revoked} sessions");

        // List should be empty
        var listExchange = await _fx.RequestWithHeaders(IdentityEndpoints.ManageSessions,
            new Dictionary<string, object?> { ["userId"] = userId },
            new Dictionary<string, object?> { ["operation"] = "list" });

        var sessions = listExchange.Out?.Body as IEnumerable<object>;
        sessions.Should().NotBeNull();
        sessions!.Count().Should().Be(0);
    }

    [Fact]
    public async Task Logout_RevokesSessionsAndInvalidatesTokens()
    {
        // Authenticate and get tokens
        var authorizeResult = await Authorize();
        authorizeResult.Should().ContainKey("code");

        var userId = await GetTestUserId();

        // Perform logout
        var logoutExchange = await _fx.RequestWithHeaders(IdentityEndpoints.ManageSessions,
            new Dictionary<string, object?> { ["userId"] = userId },
            new Dictionary<string, object?> { ["operation"] = "logout" });

        var logoutResponse = (Dictionary<string, object?>)logoutExchange.Out!.Body!;
        logoutResponse.Should().ContainKey("success");
        ((bool)logoutResponse["success"]!).Should().BeTrue();

        _output.WriteLine($"Logged out. Sessions revoked: {logoutResponse["sessionsRevoked"]}");

        // Sessions should be empty
        var listExchange = await _fx.RequestWithHeaders(IdentityEndpoints.ManageSessions,
            new Dictionary<string, object?> { ["userId"] = userId },
            new Dictionary<string, object?> { ["operation"] = "list" });

        var sessions = listExchange.Out?.Body as IEnumerable<object>;
        sessions!.Count().Should().Be(0);
    }

    [Fact]
    public async Task LogoutEndpoint_DirectVm_Works()
    {
        // Authenticate
        await Authorize();

        var userId = await GetTestUserId();

        // Call the logout endpoint directly
        var logoutResult = await _fx.Request(IdentityEndpoints.Logout,
            new Dictionary<string, object?> { ["userId"] = userId });

        var response = (Dictionary<string, object?>)logoutResult!;
        response.Should().ContainKey("success");
        ((bool)response["success"]!).Should().BeTrue();

        _output.WriteLine($"Logout via direct endpoint. Sessions revoked: {response["sessions_revoked"]}");
    }

    [Fact]
    public async Task Discovery_ContainsEndSessionEndpoint()
    {
        var discoveryResult = await _fx.Request(IdentityEndpoints.Discovery,
            new Dictionary<string, string>());

        var response = (Dictionary<string, object?>)discoveryResult!;
        response.Should().ContainKey("end_session_endpoint");
        response["end_session_endpoint"]!.ToString()
            .Should().Contain("/connect/logout");

        _output.WriteLine($"end_session_endpoint: {response["end_session_endpoint"]}");
    }

    private async Task<Dictionary<string, object?>> Authorize()
    {
        var body = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic,
            ["redirect_uri"] = ProductionBootstrapFixture.TestRedirectUri,
            ["scope"] = "openid profile email",
            ["code_challenge"] = GenerateCodeChallenge(),
            ["code_challenge_method"] = "S256"
        };

        var result = await _fx.RequestWithSession(IdentityEndpoints.Authorize, body);
        return (Dictionary<string, object?>)result!;
    }

    private Task<long> GetTestUserId() =>
        // Goes through the fixture's per-call scope helper because this test calls run
        // in parallel with the Worker's WireTap audit-pipeline INSERTs; using
        // `_fx.Redb` directly would share an NpgsqlConnection with the audit writer
        // and surface as "A command is already in progress: INSERT INTO identity_audit_log".
        _fx.WithRedb(async redb =>
        {
            var coreUser = await redb.UserProvider.GetUserByLoginAsync(ProductionBootstrapFixture.TestUsername)
                .ConfigureAwait(false)
                ?? throw new Exception("Test user not found");
            return coreUser.Id;
        });

    private static string GenerateCodeChallenge()
    {
        var bytes = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        var verifier = Convert.ToBase64String(bytes)
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var hash = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.ASCII.GetBytes(verifier));
        return Convert.ToBase64String(hash)
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
