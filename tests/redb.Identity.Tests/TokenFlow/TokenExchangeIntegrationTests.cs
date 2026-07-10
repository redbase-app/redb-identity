using System.Text;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Contracts.Routes;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.TokenFlow;

/// <summary>
/// Integration tests for Token Exchange (RFC 8693) using the PRODUCTION bootstrap.
/// Real PostgreSQL + real OpenIddict pipeline. Validates delegation and error paths.
/// </summary>
[Collection("ProductionBootstrap")]
public class TokenExchangeIntegrationTests
{
    private readonly ProductionBootstrapFixture _fx;
    private readonly ITestOutputHelper _out;

    public TokenExchangeIntegrationTests(ProductionBootstrapFixture fx, ITestOutputHelper output)
    {
        _fx = fx;
        _out = output;
    }

    private const string TokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange";
    private const string AccessTokenType = "urn:ietf:params:oauth:token-type:access_token";

    // ── Helper: obtain a valid access_token via client_credentials ──

    private async Task<string> ObtainClientCredentialsToken(string? scope = null)
    {
        var body = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret
        };
        if (scope is not null)
            body["scope"] = scope;

        var result = await _fx.Request(IdentityEndpoints.Token, body);
        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().NotContainKey("error");
        return response["access_token"]!.ToString()!;
    }

    private async Task<string> ObtainPasswordToken(string? scope = null)
    {
        var body = new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret,
            ["username"] = ProductionBootstrapFixture.TestUsername,
            ["password"] = ProductionBootstrapFixture.TestPassword
        };
        if (scope is not null)
            body["scope"] = scope;

        var result = await _fx.Request(IdentityEndpoints.Token, body);
        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().NotContainKey("error",
            because: $"password flow should succeed, got: {JsonSerializer.Serialize(result)}");
        return response["access_token"]!.ToString()!;
    }

    private static JsonElement ParseJwtPayload(string jwt)
    {
        var parts = jwt.Split('.');
        var payloadJson = Encoding.UTF8.GetString(
            Convert.FromBase64String(PadBase64(parts[1])));
        return JsonSerializer.Deserialize<JsonElement>(payloadJson);
    }

    private static string PadBase64(string base64) => (base64.Length % 4) switch
    {
        2 => base64 + "==",
        3 => base64 + "=",
        _ => base64
    };

    // ── Delegation (no actor_token → client is the actor) ──

    [Fact]
    public async Task Delegation_ClientAsActor_ReturnsNewTokenWithActClaim()
    {
        // 1. Get a user token via ROPC
        var subjectToken = await ObtainPasswordToken("openid profile");

        // 2. Exchange it — client acts as the actor (no actor_token provided)
        var body = new Dictionary<string, string>
        {
            ["grant_type"] = TokenExchangeGrantType,
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret,
            ["subject_token"] = subjectToken,
            ["subject_token_type"] = AccessTokenType
        };

        var result = await _fx.Request(IdentityEndpoints.Token, body);
        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        _out.WriteLine($"Token exchange response: {JsonSerializer.Serialize(response)}");

        response.Should().NotContainKey("error",
            because: $"delegation should succeed, got: {JsonSerializer.Serialize(result)}");
        response.Should().ContainKey("access_token");

        // 3. Verify the new token has act claim
        var newToken = response["access_token"]!.ToString()!;
        var claims = ParseJwtPayload(newToken);

        claims.TryGetProperty("sub", out var sub).Should().BeTrue();
        sub.GetString().Should().Be(_fx.TestSubjectGuid.ToString("D"),
            "subject should be preserved from the original token (public sub is the per-user GUID)");

        claims.TryGetProperty("act", out var act).Should().BeTrue(
            "delegation token should contain act claim");
        act.TryGetProperty("sub", out var actSub).Should().BeTrue();
        actSub.GetString().Should().Be(ProductionBootstrapFixture.TestClientId,
            "actor should be the requesting client");
    }

    [Fact]
    public async Task Delegation_WithActorToken_ReturnsActClaimWithActorSubject()
    {
        // 1. Get a user token (the subject)
        var subjectToken = await ObtainPasswordToken("openid profile");

        // 2. Get a service token (the actor)
        var actorToken = await ObtainClientCredentialsToken("openid");

        // 3. Exchange with explicit actor_token
        var body = new Dictionary<string, string>
        {
            ["grant_type"] = TokenExchangeGrantType,
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret,
            ["subject_token"] = subjectToken,
            ["subject_token_type"] = AccessTokenType,
            ["actor_token"] = actorToken,
            ["actor_token_type"] = AccessTokenType
        };

        var result = await _fx.Request(IdentityEndpoints.Token, body);
        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        _out.WriteLine($"Actor token exchange: {JsonSerializer.Serialize(response)}");

        response.Should().NotContainKey("error",
            because: $"delegation should succeed, got: {JsonSerializer.Serialize(result)}");
        response.Should().ContainKey("access_token");

        var newToken = response["access_token"]!.ToString()!;
        var claims = ParseJwtPayload(newToken);

        // Subject preserved
        claims.TryGetProperty("sub", out var sub).Should().BeTrue();
        sub.GetString().Should().Be(_fx.TestSubjectGuid.ToString("D"));

        // Act claim reflects the actor token's subject
        claims.TryGetProperty("act", out var act).Should().BeTrue();
        act.TryGetProperty("sub", out var actSub).Should().BeTrue();
        actSub.GetString().Should().Be(ProductionBootstrapFixture.TestClientId,
            "actor sub should come from the actor_token");
    }

    [Fact]
    public async Task Delegation_PreservesOriginalScopes()
    {
        var subjectToken = await ObtainPasswordToken("openid profile email");

        var body = new Dictionary<string, string>
        {
            ["grant_type"] = TokenExchangeGrantType,
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret,
            ["subject_token"] = subjectToken,
            ["subject_token_type"] = AccessTokenType
        };

        var result = await _fx.Request(IdentityEndpoints.Token, body);
        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().NotContainKey("error");

        var newToken = response["access_token"]!.ToString()!;
        var claims = ParseJwtPayload(newToken);

        // Scopes should be carried over
        if (claims.TryGetProperty("scope", out var scope))
        {
            var scopes = scope.GetString()!;
            scopes.Should().Contain("openid");
        }
    }

    [Fact]
    public async Task Delegation_ScopeDownscoping_Succeeds()
    {
        var subjectToken = await ObtainPasswordToken("openid profile email");

        var body = new Dictionary<string, string>
        {
            ["grant_type"] = TokenExchangeGrantType,
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret,
            ["subject_token"] = subjectToken,
            ["subject_token_type"] = AccessTokenType,
            ["scope"] = "openid" // downscope to just openid
        };

        var result = await _fx.Request(IdentityEndpoints.Token, body);
        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().NotContainKey("error",
            because: "downscoping should always succeed");
    }

    // ── Error cases ──

    [Fact]
    public async Task MissingSubjectToken_ReturnsError()
    {
        var body = new Dictionary<string, string>
        {
            ["grant_type"] = TokenExchangeGrantType,
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret,
            ["subject_token_type"] = AccessTokenType
        };

        var result = await _fx.Request(IdentityEndpoints.Token, body);
        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().ContainKey("error");
        response["error"]!.ToString().Should().Be("invalid_request");
    }

    [Fact]
    public async Task MissingSubjectTokenType_ReturnsError()
    {
        var subjectToken = await ObtainClientCredentialsToken();

        var body = new Dictionary<string, string>
        {
            ["grant_type"] = TokenExchangeGrantType,
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret,
            ["subject_token"] = subjectToken
        };

        var result = await _fx.Request(IdentityEndpoints.Token, body);
        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().ContainKey("error");
        response["error"]!.ToString().Should().Be("invalid_request");
    }

    [Fact]
    public async Task UnsupportedSubjectTokenType_ReturnsError()
    {
        var subjectToken = await ObtainClientCredentialsToken();

        var body = new Dictionary<string, string>
        {
            ["grant_type"] = TokenExchangeGrantType,
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret,
            ["subject_token"] = subjectToken,
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:refresh_token"
        };

        var result = await _fx.Request(IdentityEndpoints.Token, body);
        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().ContainKey("error");
        response["error"]!.ToString().Should().Be("invalid_request");
    }

    [Fact]
    public async Task InvalidSubjectToken_ReturnsInvalidGrant()
    {
        var body = new Dictionary<string, string>
        {
            ["grant_type"] = TokenExchangeGrantType,
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret,
            ["subject_token"] = "this-is-not-a-valid-token",
            ["subject_token_type"] = AccessTokenType
        };

        var result = await _fx.Request(IdentityEndpoints.Token, body);
        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().ContainKey("error");
        response["error"]!.ToString().Should().Be("invalid_grant");
    }

    [Fact]
    public async Task UnsupportedRequestedTokenType_ReturnsError()
    {
        var subjectToken = await ObtainClientCredentialsToken();

        var body = new Dictionary<string, string>
        {
            ["grant_type"] = TokenExchangeGrantType,
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret,
            ["subject_token"] = subjectToken,
            ["subject_token_type"] = AccessTokenType,
            ["requested_token_type"] = "urn:ietf:params:oauth:token-type:id_token"
        };

        var result = await _fx.Request(IdentityEndpoints.Token, body);
        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().ContainKey("error");
    }

    [Fact]
    public async Task ScopeEscalation_Rejected()
    {
        // Get token with limited scope
        var subjectToken = await ObtainPasswordToken("openid");

        // Try to exchange with a broader scope
        var body = new Dictionary<string, string>
        {
            ["grant_type"] = TokenExchangeGrantType,
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret,
            ["subject_token"] = subjectToken,
            ["subject_token_type"] = AccessTokenType,
            ["scope"] = "openid profile email" // escalation attempt
        };

        var result = await _fx.Request(IdentityEndpoints.Token, body);
        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().ContainKey("error");
        response["error"]!.ToString().Should().Be("invalid_scope");
    }

    [Fact]
    public async Task InvalidActorToken_ReturnsError()
    {
        var subjectToken = await ObtainPasswordToken("openid");

        var body = new Dictionary<string, string>
        {
            ["grant_type"] = TokenExchangeGrantType,
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret,
            ["subject_token"] = subjectToken,
            ["subject_token_type"] = AccessTokenType,
            ["actor_token"] = "invalid-actor-token",
            ["actor_token_type"] = AccessTokenType
        };

        var result = await _fx.Request(IdentityEndpoints.Token, body);
        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().ContainKey("error");
        response["error"]!.ToString().Should().Be("invalid_grant");
    }

    [Fact]
    public async Task ActorTokenWithoutType_ReturnsError()
    {
        var subjectToken = await ObtainPasswordToken("openid");
        var actorToken = await ObtainClientCredentialsToken();

        var body = new Dictionary<string, string>
        {
            ["grant_type"] = TokenExchangeGrantType,
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret,
            ["subject_token"] = subjectToken,
            ["subject_token_type"] = AccessTokenType,
            ["actor_token"] = actorToken
            // missing actor_token_type
        };

        var result = await _fx.Request(IdentityEndpoints.Token, body);
        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().ContainKey("error");
        response["error"]!.ToString().Should().Be("invalid_request");
    }

    // ── Exchanged token is usable ──

    [Fact]
    public async Task ExchangedToken_CanBeIntrospected()
    {
        var subjectToken = await ObtainPasswordToken("openid profile");

        // Exchange
        var exchangeBody = new Dictionary<string, string>
        {
            ["grant_type"] = TokenExchangeGrantType,
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret,
            ["subject_token"] = subjectToken,
            ["subject_token_type"] = AccessTokenType
        };

        var exchangeResult = await _fx.Request(IdentityEndpoints.Token, exchangeBody);
        var exchangeResponse = exchangeResult.Should().BeOfType<Dictionary<string, object?>>().Subject;
        exchangeResponse.Should().NotContainKey("error");
        var newToken = exchangeResponse["access_token"]!.ToString()!;

        // Introspect the exchanged token
        var introspectBody = new Dictionary<string, string>
        {
            ["token"] = newToken,
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret
        };

        var introspectResult = await _fx.Request(IdentityEndpoints.Introspect, introspectBody);
        var introspectResponse = introspectResult.Should().BeOfType<Dictionary<string, object?>>().Subject;
        _out.WriteLine($"Introspection: {JsonSerializer.Serialize(introspectResponse)}");

        introspectResponse.Should().NotContainKey("error");
        introspectResponse["active"].Should().Be(true);
        introspectResponse["sub"]!.ToString().Should().Be(_fx.TestSubjectGuid.ToString("D"));
    }

    [Fact]
    public async Task ExchangedToken_CanBeExchangedAgain_DelegationChain()
    {
        // 1. Get original user token
        var subjectToken = await ObtainPasswordToken("openid profile");

        // 2. First exchange (Service A acts on behalf of user)
        var body1 = new Dictionary<string, string>
        {
            ["grant_type"] = TokenExchangeGrantType,
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret,
            ["subject_token"] = subjectToken,
            ["subject_token_type"] = AccessTokenType
        };

        var result1 = await _fx.Request(IdentityEndpoints.Token, body1);
        var response1 = result1.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response1.Should().NotContainKey("error");
        var token1 = response1["access_token"]!.ToString()!;

        // 3. Second exchange (Service B acts on behalf of user, via Service A)
        var body2 = new Dictionary<string, string>
        {
            ["grant_type"] = TokenExchangeGrantType,
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret,
            ["subject_token"] = token1,
            ["subject_token_type"] = AccessTokenType
        };

        var result2 = await _fx.Request(IdentityEndpoints.Token, body2);
        var response2 = result2.Should().BeOfType<Dictionary<string, object?>>().Subject;
        _out.WriteLine($"Chain exchange: {JsonSerializer.Serialize(response2)}");

        response2.Should().NotContainKey("error",
            because: "chained delegation should succeed within depth limit");
        var token2 = response2["access_token"]!.ToString()!;

        // Verify nested act claim
        var claims = ParseJwtPayload(token2);
        claims.TryGetProperty("act", out var act).Should().BeTrue(
            "second exchange should have act claim");
        act.TryGetProperty("act", out _).Should().BeTrue(
            "act claim should contain nested act from first exchange (delegation chain)");
    }
}
