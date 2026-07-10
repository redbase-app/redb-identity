using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using redb.Core.Query;
using redb.Identity.Core.Models;
using redb.Identity.Contracts.Routes;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.Federation;

/// <summary>
/// Integration tests for the federation (OIDC redirect-based auth) flow.
/// Full pipeline: FederationChallenge → state encrypt → FederationCallback
/// → code exchange (via FakeFederatedAuthProvider) → user provisioning → session.
/// Uses real PostgreSQL and real route pipeline (direct-vm:// access).
/// </summary>
[Collection("Federation")]
public class FederationProcessorTests : IDisposable
{
    private readonly FederationFixture _fx;
    private readonly ITestOutputHelper _out;

    public FederationProcessorTests(FederationFixture fx, ITestOutputHelper output)
    {
        _fx = fx;
        _out = output;
    }

    public void Dispose()
    {
        _fx.FakeProvider.ChallengeHandler = null;
        _fx.FakeProvider.CallbackHandler = null;
    }

    // ═══════════════════════════════════════════════
    //  Challenge endpoint
    // ═══════════════════════════════════════════════

    [Fact]
    public async Task Challenge_ValidProvider_ReturnsRedirectUri()
    {
        var body = new Dictionary<string, object?>
        {
            ["provider"] = "fake-oidc",
            ["returnUrl"] = "/dashboard",
            ["callbackUrl"] = "https://identity.test.local/connect/federation/callback"
        };

        var result = await _fx.Request(IdentityEndpoints.FederationChallenge, body);

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().ContainKey("redirect_uri");
        response.Should().NotContainKey("error");

        var redirectUri = response["redirect_uri"]!.ToString()!;
        redirectUri.Should().StartWith("https://fake-oidc.test/authorize");
        redirectUri.Should().Contain("state=");
        _out.WriteLine($"Challenge redirect_uri: {redirectUri}");
    }

    [Fact]
    public async Task Challenge_MissingProvider_ReturnsError()
    {
        var body = new Dictionary<string, object?>
        {
            ["returnUrl"] = "/dashboard",
            ["callbackUrl"] = "https://identity.test.local/connect/federation/callback"
        };

        var result = await _fx.Request(IdentityEndpoints.FederationChallenge, body);

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response["error"].Should().Be("invalid_request");
        response["error_description"]!.ToString().Should().Contain("provider");
    }

    [Fact]
    public async Task Challenge_UnknownProvider_ReturnsError()
    {
        var body = new Dictionary<string, object?>
        {
            ["provider"] = "nonexistent-provider",
            ["callbackUrl"] = "https://identity.test.local/connect/federation/callback"
        };

        var result = await _fx.Request(IdentityEndpoints.FederationChallenge, body);

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response["error"].Should().Be("invalid_request");
        response["error_description"]!.ToString().Should().Contain("nonexistent-provider");
    }

    [Fact]
    public async Task Challenge_MissingCallbackUrl_ReturnsError()
    {
        var body = new Dictionary<string, object?>
        {
            ["provider"] = "fake-oidc"
        };

        var result = await _fx.Request(IdentityEndpoints.FederationChallenge, body);

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response["error"].Should().Be("server_error");
        response["error_description"]!.ToString().Should().Contain("Callback URL");
    }

    // ═══════════════════════════════════════════════
    //  Full Challenge → Callback flow (happy path)
    // ═══════════════════════════════════════════════

    [Fact]
    public async Task FullFlow_NewUser_CreatesUserAndSession()
    {
        var uniqueCode = Guid.NewGuid().ToString("N")[..12];
        var expectedSub = $"fed-sub-{uniqueCode}";
        var expectedEmail = $"alice-fed-{uniqueCode}@corp.example.com";

        _fx.FakeProvider.CallbackHandler = (code, codeVerifier, nonce) =>
            ExternalAuthResult.Success(
                externalId: expectedSub,
                displayName: $"Alice Fed {uniqueCode}",
                email: expectedEmail,
                givenName: "Alice",
                familyName: "Federation");

        // Step 1: Challenge → get encrypted state
        var challengeBody = new Dictionary<string, object?>
        {
            ["provider"] = "fake-oidc",
            ["returnUrl"] = "/my-app",
            ["callbackUrl"] = "https://identity.test.local/connect/federation/callback"
        };

        var challengeResult = await _fx.Request(IdentityEndpoints.FederationChallenge, challengeBody);
        var challengeResp = challengeResult.Should().BeOfType<Dictionary<string, object?>>().Subject;
        challengeResp.Should().NotContainKey("error",
            because: $"challenge should succeed, got: {challengeResp.GetValueOrDefault("error_description")}");

        // Extract the encrypted state from the redirect_uri
        var redirectUri = challengeResp["redirect_uri"]!.ToString()!;
        var stateParam = ExtractQueryParam(redirectUri, "state");
        stateParam.Should().NotBeNullOrEmpty("redirect_uri must contain state parameter");

        // Step 2: Callback → exchange code + create user + create session
        var callbackBody = new Dictionary<string, object?>
        {
            ["code"] = uniqueCode,
            ["state"] = stateParam,
            ["callbackUrl"] = "https://identity.test.local/connect/federation/callback"
        };

        var callbackResult = await _fx.Request(IdentityEndpoints.FederationCallback, callbackBody);
        var callbackResp = callbackResult.Should().BeOfType<Dictionary<string, object?>>().Subject;
        callbackResp["success"].Should().Be(true,
            because: $"callback should succeed, got: {callbackResp.GetValueOrDefault("error_description")}");

        callbackResp.Should().ContainKey("userId");
        callbackResp.Should().ContainKey("username");
        callbackResp.Should().ContainKey("sessionId");
        callbackResp["returnUrl"].Should().Be("/my-app");

        var userId = Convert.ToInt64(callbackResp["userId"]);
        var username = callbackResp["username"]!.ToString()!;
        var sessionId = Convert.ToInt64(callbackResp["sessionId"]);

        userId.Should().BeGreaterThan(0);
        sessionId.Should().BeGreaterThan(0);
        _out.WriteLine($"Created federated user: id={userId}, username={username}, sessionId={sessionId}");

        // Step 3: Verify DB state — user was auto-provisioned
        var coreUser = await _fx.Redb.UserProvider.GetUserByIdAsync(userId);
        coreUser.Should().NotBeNull("local _users row must be created");
        coreUser!.Enabled.Should().BeTrue();
        coreUser.Email.Should().Be(expectedEmail);

        // Step 4: Verify UserProps row exists with given/family name claims
        var userPropsRow = await _fx.Redb.Query<UserProps>()
            .WhereRedb(o => o.Key == userId)
            .FirstOrDefaultAsync();
        userPropsRow.Should().NotBeNull("UserProps must be created");
        userPropsRow!.Props.GivenName.Should().Be("Alice");
        userPropsRow.Props.FamilyName.Should().Be("Federation");

        // H8: per-link FederatedIdentityProps row with value_string "fake-oidc:{sub}" for reverse lookup
        var expectedKey = $"fake-oidc:{expectedSub}";
        var fedRow = await _fx.Redb.Query<FederatedIdentityProps>()
            .WhereRedb(o => o.ValueString == expectedKey)
            .FirstOrDefaultAsync();
        fedRow.Should().NotBeNull("FederatedIdentityProps reverse-lookup row must exist");
        fedRow!.key.Should().Be(userId);
    }

    [Fact]
    public async Task DirectLoginService_ResolveFederatedUser_Works()
    {
        var uniqueCode = Guid.NewGuid().ToString("N")[..12];
        var stableSub = $"stable-sub-{uniqueCode}";
        var email = $"direct-{uniqueCode}@test.com";

        var ext = ExternalAuthResult.Success(
            externalId: stableSub,
            displayName: $"Direct Test {uniqueCode}",
            email: email,
            givenName: "Direct",
            familyName: "Test");

        using var scope = _fx.ServiceProvider.CreateScope();
        var loginService = scope.ServiceProvider.GetRequiredService<LoginService>();
        var result = await loginService.ResolveFederatedUserAsync("fake-oidc", ext);

        result.Succeeded.Should().BeTrue(
            because: $"ResolveFederatedUserAsync should succeed, got: {result.ErrorMessage}");
        result.UserId.Should().BeGreaterThan(0);
        _out.WriteLine($"Direct resolve: userId={result.UserId}, username={result.Username}");
    }

    [Fact]
    public async Task FullFlow_MinimalCallback_Works()
    {
        // Exact same pattern as FullFlow_NewUser — minimal reproduction test
        var uniqueCode = Guid.NewGuid().ToString("N")[..12];
        var expectedSub = $"min-sub-{uniqueCode}";
        var expectedEmail = $"minimal-{uniqueCode}@test.com";

        _fx.FakeProvider.CallbackHandler = (code, codeVerifier, nonce) =>
            ExternalAuthResult.Success(
                externalId: expectedSub,
                displayName: $"Minimal {uniqueCode}",
                email: expectedEmail,
                givenName: "Min",
                familyName: "Test");

        var state = await DoChallenge();
        var result = await DoCallback(uniqueCode, state);
        result.Should().ContainKey("success",
            because: $"minimal callback should succeed, got: {string.Join(", ", result.Select(kv => $"{kv.Key}={kv.Value}"))}");
        result["success"].Should().Be(true);
    }

    [Fact]
    public async Task FullFlow_RepeatLogin_SyncsProfileAndReturnsSameUser()
    {
        var uniqueCode1 = Guid.NewGuid().ToString("N")[..12];
        var uniqueCode2 = Guid.NewGuid().ToString("N")[..12];
        var stableSub = $"rep-sub-{uniqueCode1}";
        var email1 = $"bob-v1-{uniqueCode1}@test.com";

        _fx.FakeProvider.CallbackHandler = (code, codeVerifier, nonce) =>
            ExternalAuthResult.Success(
                externalId: stableSub,
                displayName: $"Bob Original {uniqueCode1}",
                email: email1,
                givenName: "Bob",
                familyName: "Original");

        var state1 = await DoChallenge();
        var result1 = await DoCallback(uniqueCode1, state1);
        result1.Should().ContainKey("success",
            because: $"first login should succeed, got: {string.Join(", ", result1.Select(kv => $"{kv.Key}={kv.Value}"))}");
        result1["success"].Should().Be(true);
        var userId1 = Convert.ToInt64(result1["userId"]);
        _out.WriteLine($"First login: userId={userId1}");

        // Change profile on "external" side
        var email2 = $"bob-v2-{uniqueCode2}@test.com";
        _fx.FakeProvider.CallbackHandler = (code, codeVerifier, nonce) =>
            ExternalAuthResult.Success(
                externalId: stableSub,
                displayName: $"Bob Updated {uniqueCode1}",
                email: email2,
                givenName: "Bobby",
                familyName: "Updated");

        // Second login — same sub → same user, synced profile
        var state2 = await DoChallenge();
        var result2 = await DoCallback(uniqueCode2, state2);
        result2.Should().ContainKey("success",
            because: $"second login should succeed, got: {string.Join(", ", result2.Select(kv => $"{kv.Key}={kv.Value}"))}");
        result2["success"].Should().Be(true);
        var userId2 = Convert.ToInt64(result2["userId"]);

        userId2.Should().Be(userId1, "second login must return same user");

        // Verify profile was synced
        var coreUser = await _fx.Redb.UserProvider.GetUserByIdAsync(userId1);
        coreUser!.Name.Should().Be($"Bob Updated {uniqueCode1}");
        coreUser.Email.Should().Be(email2);

        var oidcObj = await _fx.Redb.Query<UserProps>()
            .WhereRedb(o => o.Key == userId1)
            .FirstOrDefaultAsync();
        oidcObj!.Props.GivenName.Should().Be("Bobby");
        oidcObj.Props.FamilyName.Should().Be("Updated");
    }

    // ═══════════════════════════════════════════════
    //  Callback error scenarios
    // ═══════════════════════════════════════════════

    [Fact]
    public async Task Callback_InvalidState_ReturnsError()
    {
        var body = new Dictionary<string, object?>
        {
            ["code"] = "some-code",
            ["state"] = "totally-invalid-garbage-state",
            ["callbackUrl"] = "https://identity.test.local/connect/federation/callback"
        };

        var result = await _fx.Request(IdentityEndpoints.FederationCallback, body);

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response["success"].Should().Be(false);
        response["error"].Should().Be("invalid_state");
    }

    [Fact]
    public async Task Callback_ExpiredState_ReturnsError()
    {
        // Create a valid state but with IssuedAt in the distant past
        var stateProtector = _fx.ServiceProvider.GetService(typeof(FederationStateProtector))
            as FederationStateProtector;
        stateProtector.Should().NotBeNull();

        var expiredState = stateProtector!.Protect(new FederationState
        {
            ProviderId = "fake-oidc",
            ReturnUrl = "/",
            IssuedAt = DateTimeOffset.UtcNow.AddMinutes(-30) // way past the 5-min TTL
        });

        var body = new Dictionary<string, object?>
        {
            ["code"] = "some-code",
            ["state"] = expiredState,
            ["callbackUrl"] = "https://identity.test.local/connect/federation/callback"
        };

        var result = await _fx.Request(IdentityEndpoints.FederationCallback, body);

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response["success"].Should().Be(false);
        response["error"].Should().Be("invalid_state");
    }

    [Fact]
    public async Task Callback_IdpReturnsError_PropagatesError()
    {
        var body = new Dictionary<string, object?>
        {
            ["error"] = "access_denied",
            ["error_description"] = "User denied consent"
        };

        var result = await _fx.Request(IdentityEndpoints.FederationCallback, body);

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response["success"].Should().Be(false);
        response["error"].Should().Be("access_denied");
        response["error_description"]!.ToString().Should().Contain("User denied consent");
    }

    [Fact]
    public async Task Callback_MissingCode_ReturnsError()
    {
        var stateProtector = _fx.ServiceProvider.GetService(typeof(FederationStateProtector))
            as FederationStateProtector;
        var validState = stateProtector!.Protect(new FederationState
        {
            ProviderId = "fake-oidc",
            ReturnUrl = "/"
        });

        var body = new Dictionary<string, object?>
        {
            ["state"] = validState,
            ["callbackUrl"] = "https://identity.test.local/connect/federation/callback"
        };

        var result = await _fx.Request(IdentityEndpoints.FederationCallback, body);

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response["success"].Should().Be(false);
        response["error"].Should().Be("invalid_request");
    }

    [Fact]
    public async Task Callback_ProviderReturnsFailure_ReturnsAccessDenied()
    {
        _fx.FakeProvider.CallbackHandler = (code, codeVerifier, nonce) =>
            ExternalAuthResult.Failed("Token exchange failed: bad code");

        var state = await DoChallenge();
        var result = await DoCallback("bad-code", state);

        result["success"].Should().Be(false);
        result["error"].Should().Be("access_denied");
        result["error_description"]!.ToString().Should().Contain("Token exchange failed");
    }

    [Fact]
    public async Task Callback_StateReplay_SecondUseRejected_OneTimeUse()
    {
        // C6: federation state is one-time-use. The same state blob must not be
        // accepted twice — the second callback must return invalid_state regardless
        // of whether the upstream provider would accept the code.
        var uniqueCode = Guid.NewGuid().ToString("N")[..12];
        var sub = $"replay-sub-{uniqueCode}";

        _fx.FakeProvider.CallbackHandler = (code, codeVerifier, nonce) =>
            ExternalAuthResult.Success(externalId: sub, displayName: $"Replay User {uniqueCode}", email: $"{uniqueCode}@test.com");

        // First callback with valid state — succeeds and consumes the jti.
        var state = await DoChallenge();
        var result1 = await DoCallback(uniqueCode, state);
        result1["success"].Should().Be(true);

        // Second callback with the same state — must be rejected by the nonce store.
        var result2 = await DoCallback(uniqueCode, state);
        result2["success"].Should().Be(false);
        result2["error"].Should().Be("invalid_state");
    }

    // ═══════════════════════════════════════════════
    //  Helpers
    // ═══════════════════════════════════════════════

    private async Task<string> DoChallenge(string returnUrl = "/")
    {
        var body = new Dictionary<string, object?>
        {
            ["provider"] = "fake-oidc",
            ["returnUrl"] = returnUrl,
            ["callbackUrl"] = "https://identity.test.local/connect/federation/callback"
        };

        var result = await _fx.Request(IdentityEndpoints.FederationChallenge, body);
        var resp = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        resp.Should().NotContainKey("error",
            because: $"challenge should succeed, got: {resp.GetValueOrDefault("error_description")}");

        var redirectUri = resp["redirect_uri"]!.ToString()!;
        return ExtractQueryParam(redirectUri, "state")!;
    }

    private async Task<Dictionary<string, object?>> DoCallback(string code, string state)
    {
        var body = new Dictionary<string, object?>
        {
            ["code"] = code,
            ["state"] = state,
            ["callbackUrl"] = "https://identity.test.local/connect/federation/callback"
        };

        var result = await _fx.Request(IdentityEndpoints.FederationCallback, body);
        return result.Should().BeOfType<Dictionary<string, object?>>().Subject;
    }

    private static string? ExtractQueryParam(string url, string paramName)
    {
        var uri = new Uri(url, UriKind.RelativeOrAbsolute);
        if (!uri.IsAbsoluteUri)
            uri = new Uri("http://dummy" + url);

        var query = uri.Query.TrimStart('?');
        foreach (var pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = pair.Split('=', 2);
            if (parts.Length == 2 && parts[0] == paramName)
                return Uri.UnescapeDataString(parts[1]);
        }
        return null;
    }
}
