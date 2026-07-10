using System.Text;
using System.Text.Json;
using FluentAssertions;
using redb.Core.Query;
using redb.Identity.Core.Models;
using redb.Identity.Contracts.Routes;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.ExternalProvider;

/// <summary>
/// E2E integration tests for <see cref="IExternalUserProvider"/> SPI.
/// Full pipeline: ROPC request → OpenIddict → HandleTokenRequestHandler → LoginService
/// (with DI-injected FakeExternalUserProvider) → PostgreSQL → JWT token.
/// No direct LoginService calls — everything goes through the real pipeline.
/// </summary>
[Collection("ProductionBootstrap")]
public class ExternalUserProviderTests : IDisposable
{
    private readonly ProductionBootstrapFixture _fx;
    private readonly ITestOutputHelper _out;

    public ExternalUserProviderTests(ProductionBootstrapFixture fx, ITestOutputHelper output)
    {
        _fx = fx;
        _out = output;
    }

    public void Dispose()
    {
        // Always clear handlers after each test to prevent cross-contamination
        _fx.FakeExternalProvider.UserHandlers.Clear();
    }

    private Dictionary<string, string> RopcBody(string username, string password, string scope = "openid profile email")
    {
        return new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = username,
            ["password"] = password,
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret,
            ["scope"] = scope
        };
    }

    private static JsonElement DecodeJwtPayload(string jwt)
    {
        var parts = jwt.Split('.');
        var json = Encoding.UTF8.GetString(Convert.FromBase64String(PadBase64(parts[1])));
        return JsonSerializer.Deserialize<JsonElement>(json);
    }

    private static string PadBase64(string b64) => (b64.Length % 4) switch
    {
        2 => b64 + "==",
        3 => b64 + "=",
        _ => b64
    };

    // ─────────────────────────────────────────────
    //  1. Happy path: external auth → new user → token
    // ─────────────────────────────────────────────

    [Fact]
    public async Task ExternalAuth_NewUser_CreatesUserAndIssuesJwtWithClaims()
    {
        var extUsername = $"ext_e2e_a_{Guid.NewGuid():N}"[..20];

        _fx.FakeExternalProvider.UserHandlers[extUsername] = password =>
            password == "ext-secret"
                ? ExternalAuthResult.Success(
                    externalId: $"cn={extUsername},ou=users,dc=corp",
                    displayName: $"Alice {extUsername}",
                    email: "alice-e2e@corp.example.com",
                    givenName: "Alice",
                    familyName: "External",
                    additionalClaims: new Dictionary<string, string> { ["department"] = "R&D" })
                : ExternalAuthResult.Failed("Wrong password");

        // Full ROPC pipeline request
        var result = await _fx.Request(IdentityEndpoints.Token, RopcBody(extUsername, "ext-secret"));

        // 1) Token response
        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().NotContainKey("error",
            because: $"ROPC should succeed, got: {response.GetValueOrDefault("error_description")}");
        response.Should().ContainKey("access_token");
        var accessToken = response["access_token"]!.ToString()!;
        _out.WriteLine($"access_token length={accessToken.Length}");

        // 2) JWT claims (proves IdentityPrincipalBuilder wired the external profile)
        var claims = DecodeJwtPayload(accessToken);

        claims.TryGetProperty("sub", out _).Should().BeTrue("JWT must contain sub");
        claims.TryGetProperty("name", out var name).Should().BeTrue("JWT must contain name");
        name.GetString().Should().Be(extUsername);

        claims.TryGetProperty("given_name", out var gn).Should().BeTrue("JWT must contain given_name");
        gn.GetString().Should().Be("Alice");

        claims.TryGetProperty("family_name", out var fn).Should().BeTrue("JWT must contain family_name");
        fn.GetString().Should().Be("External");

        claims.TryGetProperty("email", out var email).Should().BeTrue("JWT must contain email");
        email.GetString().Should().Be("alice-e2e@corp.example.com");

        // 3) DB state (proves LoginService.ResolveExternalUser created user + UserProps)
        var coreUser = await _fx.Redb.UserProvider.GetUserByLoginAsync(extUsername);
        coreUser.Should().NotBeNull("local _users row must be created");
        coreUser!.Enabled.Should().BeTrue();
        coreUser.CodeString.Should().Be("fake-test", "CodeString must store provider name");

        var oidcObj = await _fx.Redb.Query<UserProps>()
            .WhereRedb(o => o.Key == coreUser.Id)
            .FirstOrDefaultAsync();
        oidcObj.Should().NotBeNull("UserProps must be created");
        oidcObj!.Props.ExternalIdentities.Should().ContainKey("fake-test");
        oidcObj.Props.ExternalIdentities!["fake-test"].Sub.Should().Contain(extUsername);
        oidcObj.Props.GivenName.Should().Be("Alice");
        oidcObj.Props.FamilyName.Should().Be("External");
        oidcObj.Props.CustomClaims.Should().ContainKey("department");
        oidcObj.Props.CustomClaims!["department"].Should().Be("R&D");
    }

    // ─────────────────────────────────────────────
    //  2. Repeat login: profile synced, same user ID
    // ─────────────────────────────────────────────

    [Fact]
    public async Task ExternalAuth_SecondLogin_SyncsProfileAndReturnsSameSubject()
    {
        var extUsername = $"ext_e2e_b_{Guid.NewGuid():N}"[..20];

        _fx.FakeExternalProvider.UserHandlers[extUsername] = password =>
            password == "bob-pass"
                ? ExternalAuthResult.Success(
                    externalId: $"cn={extUsername},dc=corp",
                    displayName: $"Bob {extUsername}",
                    email: "bob-v1@corp.example.com",
                    phone: "+1000000001",
                    givenName: "Bob",
                    familyName: "Original")
                : ExternalAuthResult.Failed("Wrong password");

        // First ROPC — creates user
        var result1 = await _fx.Request(IdentityEndpoints.Token, RopcBody(extUsername, "bob-pass", "openid profile email phone"));
        var resp1 = result1.Should().BeOfType<Dictionary<string, object?>>().Subject;
        resp1.Should().NotContainKey("error");
        var sub1 = DecodeJwtPayload(resp1["access_token"]!.ToString()!)
            .GetProperty("sub").GetString();
        _out.WriteLine($"First login sub={sub1}");

        // Verify first-login _users state
        var user1 = await _fx.Redb.UserProvider.GetUserByLoginAsync(extUsername);
        user1!.Email.Should().Be("bob-v1@corp.example.com");
        user1.Phone.Should().Be("+1000000001");

        // Change profile on external side (email, phone, name all change)
        _fx.FakeExternalProvider.UserHandlers[extUsername] = password =>
            password == "bob-pass"
                ? ExternalAuthResult.Success(
                    externalId: $"cn={extUsername},dc=corp",
                    displayName: $"BobUp {extUsername}",
                    email: "bob-v2@corp.example.com",
                    phone: "+2000000002",
                    givenName: "Bobby",
                    familyName: "Updated")
                : ExternalAuthResult.Failed("Wrong password");

        // Second ROPC — finds existing user, syncs profile
        var result2 = await _fx.Request(IdentityEndpoints.Token, RopcBody(extUsername, "bob-pass", "openid profile email phone"));
        var resp2 = result2.Should().BeOfType<Dictionary<string, object?>>().Subject;
        resp2.Should().NotContainKey("error");
        var sub2 = DecodeJwtPayload(resp2["access_token"]!.ToString()!)
            .GetProperty("sub").GetString();

        sub2.Should().Be(sub1, "second login must return same user");

        // JWT claims synced
        var claims2 = DecodeJwtPayload(resp2["access_token"]!.ToString()!);
        claims2.GetProperty("given_name").GetString().Should().Be("Bobby");
        claims2.GetProperty("family_name").GetString().Should().Be("Updated");
        claims2.GetProperty("email").GetString().Should().Be("bob-v2@corp.example.com");

        // _users row updated (authoritative sync from external)
        var user2 = await _fx.Redb.UserProvider.GetUserByLoginAsync(extUsername);
        user2!.Email.Should().Be("bob-v2@corp.example.com", "_users.Email must be synced");
        user2.Phone.Should().Be("+2000000002", "_users.Phone must be synced");
        user2.Name.Should().Be($"BobUp {extUsername}", "_users.Name must be synced");

        // UserProps updated — sub is now a GUID, so look up by the local user id.
        var oidcObj = await _fx.Redb.Query<UserProps>()
            .WhereRedb(o => o.Key == user2.Id)
            .FirstOrDefaultAsync();
        oidcObj!.value_guid!.Value.ToString("D").Should().Be(sub1,
            "the public sub claim must equal UserProps.value_guid for the same user");
        oidcObj.Props.GivenName.Should().Be("Bobby");
        oidcObj.Props.FamilyName.Should().Be("Updated");
        oidcObj.Props.EmailVerified.Should().BeTrue();
        oidcObj.Props.PhoneNumberVerified.Should().BeTrue();
    }

    // ─────────────────────────────────────────────
    //  3. Explicit reject: provider returns Failed → no local fallthrough
    // ─────────────────────────────────────────────

    [Fact]
    public async Task ExternalAuth_ExplicitReject_ReturnsAccessDenied_NoFallthrough()
    {
        var extUsername = $"ext_e2e_e_{Guid.NewGuid():N}"[..20];

        // Provider CLAIMS this user but rejects — must NOT fall through to local
        _fx.FakeExternalProvider.UserHandlers[extUsername] = _ =>
            ExternalAuthResult.Failed("LDAP bind failed: invalid credentials");

        var result = await _fx.Request(IdentityEndpoints.Token, RopcBody(extUsername, "wrong-pass"));

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().ContainKey("error");
        response["error"].Should().Be("access_denied");
    }

    // ─────────────────────────────────────────────
    //  4. Provider returns null → fallback to local auth
    // ─────────────────────────────────────────────

    [Fact]
    public async Task ExternalAuth_ProviderSkips_FallsBackToLocal()
    {
        var localUsername = $"ext_e2e_l_{Guid.NewGuid():N}"[..20];
        var localPassword = "Local@Pass1";

        await _fx.Redb.UserProvider.CreateUserAsync(new redb.Core.Models.Users.CreateUserRequest
        {
            Login = localUsername,
            Password = localPassword,
            Name = $"LocalE2E {localUsername}",
            Email = "locale2e@test.com",
            Enabled = true
        });

        // FakeProvider has NO handler for this user → returns null → skip
        // (handlers are cleared by Dispose, but we also don't add any)

        var result = await _fx.Request(IdentityEndpoints.Token, RopcBody(localUsername, localPassword));

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().NotContainKey("error",
            because: $"local fallback should work, got: {response.GetValueOrDefault("error_description")}");
        response.Should().ContainKey("access_token");

        // JWT sub = the public per-user GUID (UserProps.value_guid).
        // The bigint local user-id is mirrored into the internal `redb:user_id` claim.
        var claims = DecodeJwtPayload(response["access_token"]!.ToString()!);
        var coreUser = await _fx.Redb.UserProvider.GetUserByLoginAsync(localUsername);
        var oidcObj = await _fx.Redb.Query<redb.Identity.Core.Models.UserProps>()
            .WhereRedb(o => o.Key == coreUser!.Id)
            .FirstOrDefaultAsync();
        oidcObj.Should().NotBeNull("LoginService persists UserProps with value_guid on first login");
        oidcObj!.value_guid.Should().NotBeNull().And.NotBe(Guid.Empty);
        claims.GetProperty("sub").GetString().Should().Be(oidcObj.value_guid!.Value.ToString("D"));
        claims.GetProperty("redb:user_id").GetString().Should().Be(coreUser!.Id.ToString());
        _out.WriteLine($"Local fallback OK: sub={oidcObj.value_guid}, internal_uid={coreUser.Id}");
    }

    // ─────────────────────────────────────────────
    //  5. Provider throws exception → skipped → fallback to local
    // ─────────────────────────────────────────────

    [Fact]
    public async Task ExternalAuth_ProviderThrows_SkippedGracefully_FallbackWorks()
    {
        var throwUsername = $"ext_e2e_t_{Guid.NewGuid():N}"[..20];
        var localPassword = "Fallback@Pass1";

        await _fx.Redb.UserProvider.CreateUserAsync(new redb.Core.Models.Users.CreateUserRequest
        {
            Login = throwUsername,
            Password = localPassword,
            Name = $"FallbackE2E {throwUsername}",
            Enabled = true
        });

        // Provider blows up → must be caught and skipped
        _fx.FakeExternalProvider.UserHandlers[throwUsername] = _ =>
            throw new InvalidOperationException("LDAP server unreachable");

        var result = await _fx.Request(IdentityEndpoints.Token, RopcBody(throwUsername, localPassword));

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().NotContainKey("error",
            because: $"provider exception must not bubble, got: {response.GetValueOrDefault("error_description")}");
        response.Should().ContainKey("access_token");
    }

    // ─────────────────────────────────────────────
    //  6. Disabled user → reject even if external provider says yes
    // ─────────────────────────────────────────────

    [Fact]
    public async Task ExternalAuth_DisabledUser_RejectsEvenIfExternalSucceeds()
    {
        var extUsername = $"ext_e2e_d_{Guid.NewGuid():N}"[..20];

        await _fx.Redb.UserProvider.CreateUserAsync(new redb.Core.Models.Users.CreateUserRequest
        {
            Login = extUsername,
            Password = "Dummy@Pass1",
            Name = $"DisabledE2E {extUsername}",
            Enabled = false
        });

        _fx.FakeExternalProvider.UserHandlers[extUsername] = _ =>
            ExternalAuthResult.Success(
                externalId: $"cn={extUsername},dc=corp",
                displayName: $"Dis {extUsername}");

        var result = await _fx.Request(IdentityEndpoints.Token, RopcBody(extUsername, "any-pass"));

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().ContainKey("error");
        response["error"].Should().Be("access_denied");
    }

    // ─────────────────────────────────────────────
    //  7. Wrong password on external provider → proper OAuth2 error
    // ─────────────────────────────────────────────

    [Fact]
    public async Task ExternalAuth_WrongPassword_ReturnsAccessDenied()
    {
        var extUsername = $"ext_e2e_w_{Guid.NewGuid():N}"[..20];

        _fx.FakeExternalProvider.UserHandlers[extUsername] = password =>
            password == "correct-pass"
                ? ExternalAuthResult.Success(
                    externalId: "cn=test,dc=corp",
                    displayName: "Test User")
                : ExternalAuthResult.Failed("Bad credentials");

        var result = await _fx.Request(IdentityEndpoints.Token, RopcBody(extUsername, "wrong-pass"));

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().ContainKey("error");
        response["error"].Should().Be("access_denied");
    }
}
