using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using redb.Core.Query;
using redb.Identity.Core.Models;
using redb.Identity.Contracts.Routes;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.Federation;

/// <summary>
/// End-to-end federation tests against a real mock-oauth2-server (navikt).
/// Validates the complete OIDC flow: discovery → PKCE challenge → interactive login
/// → authorization code → token exchange → id_token validation → user provisioning.
/// Requires: <c>route-mock-oauth2</c> container on port 9199.
/// </summary>
[Collection("MockOidcE2E")]
public class MockOidcE2ETests
{
    private readonly MockOidcE2EFixture _fx;
    private readonly ITestOutputHelper _out;

    public MockOidcE2ETests(MockOidcE2EFixture fx, ITestOutputHelper output)
    {
        _fx = fx;
        _out = output;
    }

    private bool EnsureServerAvailable()
    {
        if (!_fx.IsServerAvailable)
        {
            _out.WriteLine("[SKIP] mock-oauth2-server is not available at " + MockOidcE2EFixture.Authority);
            return false;
        }
        return true;
    }

    // ═══════════════════════════════════════════════
    //  Discovery
    // ═══════════════════════════════════════════════

    [Fact]
    public async Task Discovery_MockOidcServer_IsReachable()
    {
        if (!EnsureServerAvailable()) return;

        using var http = new HttpClient();
        var disco = await http.GetStringAsync(
            $"{MockOidcE2EFixture.Authority}/.well-known/openid-configuration");

        disco.Should().Contain("authorization_endpoint");
        disco.Should().Contain("token_endpoint");
        disco.Should().Contain("jwks_uri");
        _out.WriteLine("mock-oauth2-server discovery OK");
    }

    // ═══════════════════════════════════════════════
    //  Full E2E: Challenge → Interactive Login → Callback → User
    // ═══════════════════════════════════════════════

    [Fact]
    public async Task FullE2E_NewUser_RealOidcFlow()
    {
        if (!EnsureServerAvailable()) return;

        var uniqueId = Guid.NewGuid().ToString("N")[..8];
        var mockUsername = $"e2e-user-{uniqueId}";

        // Step 1: Challenge → get redirect URL pointing to real mock-oauth2-server
        var challengeBody = new Dictionary<string, object?>
        {
            ["provider"] = MockOidcE2EFixture.ProviderId,
            ["returnUrl"] = "/e2e-dashboard",
            ["callbackUrl"] = MockOidcE2EFixture.CallbackUrl
        };

        var challengeResult = await _fx.Request(IdentityEndpoints.FederationChallenge, challengeBody);
        var challengeResp = challengeResult.Should().BeOfType<Dictionary<string, object?>>().Subject;
        challengeResp.Should().NotContainKey("error",
            because: $"challenge should succeed, got: {challengeResp.GetValueOrDefault("error_description")}");

        var redirectUri = challengeResp["redirect_uri"]!.ToString()!;
        _out.WriteLine($"Challenge redirect: {redirectUri}");

        // Verify the redirect points to real mock-oauth2-server
        redirectUri.Should().StartWith(MockOidcE2EFixture.Authority);
        redirectUri.Should().Contain("response_type=code");
        redirectUri.Should().Contain("code_challenge_method=S256");
        redirectUri.Should().Contain("code_challenge="); // PKCE

        // Extract the encrypted state from the redirect URL
        var encryptedState = MockOidcE2EFixture.ExtractQueryParam(redirectUri, "state");
        encryptedState.Should().NotBeNullOrEmpty();

        // Step 2: Simulate browser login on mock-oauth2-server
        var (code, returnedState) = await _fx.SimulateInteractiveLogin(redirectUri, mockUsername);
        _out.WriteLine($"Mock login complete: code={code[..8]}..., state matches={returnedState == encryptedState}");

        returnedState.Should().Be(encryptedState, "mock-oauth2-server should echo our state");

        // Step 3: Callback → code exchange (real token endpoint) → user provisioning
        var callbackBody = new Dictionary<string, object?>
        {
            ["code"] = code,
            ["state"] = encryptedState,
            ["callbackUrl"] = MockOidcE2EFixture.CallbackUrl
        };

        var callbackResult = await _fx.Request(IdentityEndpoints.FederationCallback, callbackBody);
        var callbackResp = callbackResult.Should().BeOfType<Dictionary<string, object?>>().Subject;
        callbackResp.Should().ContainKey("success");
        callbackResp["success"].Should().Be(true,
            because: $"callback should succeed, got error: {callbackResp.GetValueOrDefault("error")} / {callbackResp.GetValueOrDefault("error_description")}");

        callbackResp.Should().ContainKey("userId");
        callbackResp.Should().ContainKey("sessionId");
        callbackResp.Should().ContainKey("username");
        callbackResp["returnUrl"].Should().Be("/e2e-dashboard");

        var userId = Convert.ToInt64(callbackResp["userId"]);
        var sessionId = Convert.ToInt64(callbackResp["sessionId"]);
        userId.Should().BeGreaterThan(0);
        sessionId.Should().BeGreaterThan(0);
        _out.WriteLine($"User provisioned: userId={userId}, sessionId={sessionId}, username={callbackResp["username"]}");

        // Step 4: Verify DB — UserProps row + per-link FederatedIdentityProps row exist (H8).
        var userPropsRow = await _fx.Redb.Query<UserProps>()
            .WhereRedb(o => o.Key == userId)
            .FirstOrDefaultAsync();
        userPropsRow.Should().NotBeNull("UserProps must be created for federated user");

        // Per-link reverse-lookup row: value_string format "{providerId}:{sub}".
        var providerPrefix = MockOidcE2EFixture.ProviderId + ":";
        var fedRow = await _fx.Redb.Query<FederatedIdentityProps>()
            .WhereRedb(o => o.Key == userId)
            .FirstOrDefaultAsync();
        fedRow.Should().NotBeNull("FederatedIdentityProps row must be created for the link");
        fedRow!.value_string.Should().StartWith(providerPrefix);
        _out.WriteLine($"Federated link stored: value_string={fedRow.value_string}");
    }

    [Fact]
    public async Task FullE2E_RepeatLogin_ReturnsSameUser()
    {
        if (!EnsureServerAvailable()) return;

        var uniqueId = Guid.NewGuid().ToString("N")[..8];
        var mockUsername = $"e2e-repeat-{uniqueId}";

        // First login
        var (userId1, sessionId1) = await DoFullE2EFlow(mockUsername);
        _out.WriteLine($"First login: userId={userId1}, sessionId={sessionId1}");

        // Second login with same username (same sub from mock-oauth2-server)
        var (userId2, sessionId2) = await DoFullE2EFlow(mockUsername);
        _out.WriteLine($"Second login: userId={userId2}, sessionId={sessionId2}");

        userId2.Should().Be(userId1, "repeat login should resolve the same user");
        sessionId2.Should().NotBe(sessionId1, "each login should create a new session");
    }

    [Fact]
    public async Task FullE2E_DifferentUsers_CreateDifferentAccounts()
    {
        if (!EnsureServerAvailable()) return;

        var uniqueId = Guid.NewGuid().ToString("N")[..8];

        var (userId1, _) = await DoFullE2EFlow($"e2e-alice-{uniqueId}");
        var (userId2, _) = await DoFullE2EFlow($"e2e-bob-{uniqueId}");

        userId1.Should().NotBe(userId2, "different IdP users should get different local accounts");
        _out.WriteLine($"Alice={userId1}, Bob={userId2}");
    }

    [Fact]
    public async Task Challenge_RealDiscovery_ContainsPkceAndScopes()
    {
        if (!EnsureServerAvailable()) return;

        var challengeBody = new Dictionary<string, object?>
        {
            ["provider"] = MockOidcE2EFixture.ProviderId,
            ["returnUrl"] = "/",
            ["callbackUrl"] = MockOidcE2EFixture.CallbackUrl
        };

        var challengeResult = await _fx.Request(IdentityEndpoints.FederationChallenge, challengeBody);
        var resp = challengeResult.Should().BeOfType<Dictionary<string, object?>>().Subject;
        resp.Should().NotContainKey("error");

        var redirectUri = resp["redirect_uri"]!.ToString()!;

        // Verify PKCE parameters are present
        MockOidcE2EFixture.ExtractQueryParam(redirectUri, "code_challenge").Should().NotBeNullOrEmpty();
        MockOidcE2EFixture.ExtractQueryParam(redirectUri, "code_challenge_method").Should().Be("S256");

        // Verify scopes
        var scope = MockOidcE2EFixture.ExtractQueryParam(redirectUri, "scope");
        scope.Should().Contain("openid");

        // Verify nonce
        MockOidcE2EFixture.ExtractQueryParam(redirectUri, "nonce").Should().NotBeNullOrEmpty();

        _out.WriteLine($"PKCE + scopes + nonce verified in authorize URL");
    }

    // ═══════════════════════════════════════════════
    //  Helpers
    // ═══════════════════════════════════════════════

    private async Task<(long userId, long sessionId)> DoFullE2EFlow(string mockUsername)
    {
        var challengeBody = new Dictionary<string, object?>
        {
            ["provider"] = MockOidcE2EFixture.ProviderId,
            ["returnUrl"] = "/",
            ["callbackUrl"] = MockOidcE2EFixture.CallbackUrl
        };

        var challengeResult = await _fx.Request(IdentityEndpoints.FederationChallenge, challengeBody);
        var challengeResp = challengeResult.Should().BeOfType<Dictionary<string, object?>>().Subject;
        challengeResp.Should().NotContainKey("error",
            because: $"challenge failed: {challengeResp.GetValueOrDefault("error_description")}");

        var redirectUri = challengeResp["redirect_uri"]!.ToString()!;
        var encryptedState = MockOidcE2EFixture.ExtractQueryParam(redirectUri, "state")!;

        var (code, _) = await _fx.SimulateInteractiveLogin(redirectUri, mockUsername);

        var callbackBody = new Dictionary<string, object?>
        {
            ["code"] = code,
            ["state"] = encryptedState,
            ["callbackUrl"] = MockOidcE2EFixture.CallbackUrl
        };

        var callbackResult = await _fx.Request(IdentityEndpoints.FederationCallback, callbackBody);
        var resp = callbackResult.Should().BeOfType<Dictionary<string, object?>>().Subject;
        resp["success"].Should().Be(true,
            because: $"E2E flow failed: {resp.GetValueOrDefault("error")} / {resp.GetValueOrDefault("error_description")}");

        return (Convert.ToInt64(resp["userId"]), Convert.ToInt64(resp["sessionId"]));
    }
}
