using FluentAssertions;
using redb.Identity.Contracts.Routes;
using redb.Identity.Tests.Infrastructure;
using redb.Route.Abstractions;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.TokenFlow;

/// <summary>
/// Integration tests for the Device Code Flow (RFC 8628) using PRODUCTION bootstrap.
/// Real PostgreSQL stores, real OpenIddict pipeline — no degraded mode.
/// Validates: device authorization → user verification → token exchange.
/// </summary>
[Collection("ProductionBootstrap")]
public class DeviceCodeFlowIntegrationTests
{
    private readonly ProductionBootstrapFixture _fx;
    private readonly ITestOutputHelper _out;

    public DeviceCodeFlowIntegrationTests(ProductionBootstrapFixture fx, ITestOutputHelper o)
    {
        _fx = fx;
        _out = o;
    }

    [Fact]
    public async Task DeviceAuthorization_ReturnsDeviceCode()
    {
        var body = new Dictionary<string, string>
        {
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic
        };

        var result = await _fx.Request(IdentityEndpoints.Device, body);

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().NotContainKey("error",
            because: $"device authorization should succeed, got: {(response.ContainsKey("error_description") ? response["error_description"] : "n/a")}");
        response.Should().ContainKey("device_code");
        response["device_code"]!.ToString().Should().NotBeEmpty();
        response.Should().ContainKey("user_code");
        response["user_code"]!.ToString().Should().NotBeEmpty();
        response.Should().ContainKey("verification_uri");
        response.Should().ContainKey("expires_in");
    }

    [Fact]
    public async Task DeviceToken_BeforeVerification_ReturnsPending()
    {
        // Step 1: Get device code
        var deviceBody = new Dictionary<string, string>
        {
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic
        };

        var deviceResult = await _fx.Request(IdentityEndpoints.Device, deviceBody);
        var deviceResponse = deviceResult.Should().BeOfType<Dictionary<string, object?>>().Subject;
        deviceResponse.Should().ContainKey("device_code");
        var deviceCode = deviceResponse["device_code"]!.ToString()!;

        // Step 2: Try token exchange immediately (before user verification)
        var tokenBody = new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code",
            ["device_code"] = deviceCode,
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic
        };

        var tokenResult = await _fx.Request(IdentityEndpoints.Token, tokenBody);
        var tokenResponse = tokenResult.Should().BeOfType<Dictionary<string, object?>>().Subject;

        tokenResponse.Should().ContainKey("error");
        tokenResponse["error"].Should().Be("authorization_pending");
    }

    [Fact]
    public async Task FullDeviceCodeFlow_AuthorizesAndIssuesToken()
    {
        // Step 1: Device authorization — get device_code and user_code
        var deviceBody = new Dictionary<string, string>
        {
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic
        };

        var deviceResult = await _fx.Request(IdentityEndpoints.Device, deviceBody);
        var deviceResponse = deviceResult.Should().BeOfType<Dictionary<string, object?>>().Subject;
        deviceResponse.Should().NotContainKey("error",
            because: $"device auth should succeed, got: {(deviceResponse.ContainsKey("error_description") ? deviceResponse["error_description"] : "n/a")}");

        var deviceCode = deviceResponse["device_code"]!.ToString()!;
        var userCode = deviceResponse["user_code"]!.ToString()!;

        // Step 2: User verification — authenticate and approve the device
        var verifyBody = new Dictionary<string, string>
        {
            ["user_code"] = userCode,
            ["username"] = ProductionBootstrapFixture.TestUsername,
            ["password"] = ProductionBootstrapFixture.TestPassword
        };

        var verifyExchange = await _fx.RequestWithHeaders(IdentityEndpoints.Verification, verifyBody,
            new Dictionary<string, object?>());
        var verifyResult = verifyExchange.Out?.Body;
        _out.WriteLine($"Verify result: {System.Text.Json.JsonSerializer.Serialize(verifyResult)}");
        if (verifyExchange.Exception != null)
            _out.WriteLine($"Verify exception: {verifyExchange.Exception}");

        var verifyResponse = verifyResult.Should().BeOfType<Dictionary<string, object?>>().Subject;
        verifyResponse.Should().NotContainKey("error",
            because: $"verification should succeed, got: {(verifyResponse.ContainsKey("error_description") ? verifyResponse["error_description"] : "n/a")}");

        // Step 3: Token exchange — device_code grant type
        var tokenBody = new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code",
            ["device_code"] = deviceCode,
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic
        };

        var tokenExchange = await _fx.RequestWithHeaders(IdentityEndpoints.Token, tokenBody,
            new Dictionary<string, object?>());
        _out.WriteLine($"Token result: {System.Text.Json.JsonSerializer.Serialize(tokenExchange.Out?.Body)}");
        if (tokenExchange.Exception != null)
            _out.WriteLine($"Token exception: {tokenExchange.Exception}");

        var tokenResult = tokenExchange.Out?.Body;
        var tokenResponse = tokenResult.Should().BeOfType<Dictionary<string, object?>>().Subject;

        tokenResponse.Should().NotContainKey("error",
            because: $"token exchange should succeed, got: {(tokenResponse.ContainsKey("error_description") ? tokenResponse["error_description"] : "n/a")}");
        tokenResponse.Should().ContainKey("access_token");
        tokenResponse["access_token"]!.ToString().Should().NotBeEmpty();
        tokenResponse["token_type"].Should().Be("Bearer");
    }

    [Fact]
    public async Task Verification_InvalidCredentials_ReturnsDenied()
    {
        // Step 1: Get device code
        var deviceBody = new Dictionary<string, string>
        {
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic
        };

        var deviceResult = await _fx.Request(IdentityEndpoints.Device, deviceBody);
        var deviceResponse = deviceResult.Should().BeOfType<Dictionary<string, object?>>().Subject;
        var userCode = deviceResponse["user_code"]!.ToString()!;

        // Step 2: Try verification with wrong password
        var verifyBody = new Dictionary<string, string>
        {
            ["user_code"] = userCode,
            ["username"] = ProductionBootstrapFixture.TestUsername,
            ["password"] = "WrongPassword123!"
        };

        var verifyResult = await _fx.Request(IdentityEndpoints.Verification, verifyBody);
        var verifyResponse = verifyResult.Should().BeOfType<Dictionary<string, object?>>().Subject;

        verifyResponse.Should().ContainKey("error");
        verifyResponse["error"].Should().Be("access_denied");
    }

    // -----------------------------------------------------------------------
    // N-5 — bearer-relayed verification path (RFC 8628 §3.3, BFF-relayed).
    // The host's HandleVerificationRequestHandler accepts either form credentials
    // (legacy direct host-UI path) OR an Authorization: Bearer access_token (new
    // BFF-relayed path). Tests below cover the bearer path end-to-end.
    // The bearer token is delivered to the OpenIddict server via the
    // `access_token` route header (set by HttpIdentityProcessors.ExtractBearerToken
    // on the HTTP edge — see HttpFacadeRouteBuilder.cs).
    // -----------------------------------------------------------------------

    private async Task<string> MintAccessTokenViaPasswordAsync()
    {
        var tokenBody = new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = ProductionBootstrapFixture.TestUsername,
            ["password"] = ProductionBootstrapFixture.TestPassword,
            ["client_id"] = ProductionBootstrapFixture.TestClientId,
            ["client_secret"] = ProductionBootstrapFixture.TestClientSecret,
            ["scope"] = "openid"
        };
        var result = await _fx.Request(IdentityEndpoints.Token, tokenBody);
        var resp = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        resp.Should().NotContainKey("error",
            because: $"password grant must succeed to mint a bearer for the verification test, got: {(resp.ContainsKey("error_description") ? resp["error_description"] : "n/a")}");
        var accessToken = resp["access_token"]!.ToString()!;
        accessToken.Should().NotBeNullOrEmpty();
        return accessToken;
    }

    [Fact]
    public async Task Verification_WithValidBearerToken_BuildsPrincipalWithoutPassword()
    {
        // Arrange — mint a real access_token for the test user, then start a device flow.
        var accessToken = await MintAccessTokenViaPasswordAsync();

        var deviceBody = new Dictionary<string, string>
        {
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic
        };
        var deviceResult = await _fx.Request(IdentityEndpoints.Device, deviceBody);
        var deviceResponse = deviceResult.Should().BeOfType<Dictionary<string, object?>>().Subject;
        var deviceCode = deviceResponse["device_code"]!.ToString()!;
        var userCode = deviceResponse["user_code"]!.ToString()!;

        // Act — POST verification with ONLY the bearer header (no username/password).
        var verifyBody = new Dictionary<string, string>
        {
            ["user_code"] = userCode
        };
        var verifyExchange = await _fx.RequestWithHeaders(
            IdentityEndpoints.Verification,
            verifyBody,
            new Dictionary<string, object?>
            {
                ["access_token"] = accessToken
            });

        var verifyResponse = (verifyExchange.Out?.Body as Dictionary<string, object?>)!;
        verifyResponse.Should().NotBeNull();
        _out.WriteLine($"Verify result: {System.Text.Json.JsonSerializer.Serialize(verifyResponse)}");
        if (verifyExchange.Exception != null)
            _out.WriteLine($"Verify exception: {verifyExchange.Exception}");
        verifyResponse.Should().NotContainKey("error",
            because: $"bearer-relayed verification should succeed, got: {(verifyResponse.ContainsKey("error_description") ? verifyResponse["error_description"] : "n/a")}");

        // Sanity — polling /token must now return real tokens (the device_code was approved).
        var tokenBody = new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code",
            ["device_code"] = deviceCode,
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic
        };
        var tokenResult = await _fx.Request(IdentityEndpoints.Token, tokenBody);
        var tokenResponse = tokenResult.Should().BeOfType<Dictionary<string, object?>>().Subject;
        tokenResponse.Should().NotContainKey("error");
        tokenResponse.Should().ContainKey("access_token");
        tokenResponse["access_token"]!.ToString().Should().NotBeEmpty();
    }

    [Fact]
    public async Task Verification_WithMalformedBearerToken_ReturnsLoginRequired()
    {
        // Arrange — start a device flow.
        var deviceBody = new Dictionary<string, string>
        {
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic
        };
        var deviceResult = await _fx.Request(IdentityEndpoints.Device, deviceBody);
        var deviceResponse = deviceResult.Should().BeOfType<Dictionary<string, object?>>().Subject;
        var userCode = deviceResponse["user_code"]!.ToString()!;

        // Act — bearer is garbage and no username/password in body. Bearer validation
        // fails silently and (without form creds) the handler then emits login_required.
        // Security property under test: a malformed bearer MUST NOT bypass authentication.
        var verifyBody = new Dictionary<string, string>
        {
            ["user_code"] = userCode
        };
        var verifyExchange = await _fx.RequestWithHeaders(
            IdentityEndpoints.Verification,
            verifyBody,
            new Dictionary<string, object?>
            {
                ["access_token"] = "not-a-valid-jwt"
            });

        var verifyResponse = (verifyExchange.Out?.Body as Dictionary<string, object?>)!;
        verifyResponse.Should().NotBeNull();
        verifyResponse.Should().ContainKey("error");
        verifyResponse["error"].Should().Be("login_required");
    }

    [Fact]
    public async Task Verification_WithTamperedBearerToken_ReturnsLoginRequired()
    {
        // Arrange — mint a real token, then mutate its signature so signature
        // validation fails (issuer/lifetime would otherwise pass).
        var accessToken = await MintAccessTokenViaPasswordAsync();
        var parts = accessToken.Split('.');
        parts.Should().HaveCount(3);
        // Flip the last character of the signature segment.
        var sig = parts[2];
        var tamperedSigChar = sig[^1] == 'A' ? 'B' : 'A';
        parts[2] = sig[..^1] + tamperedSigChar;
        var tampered = string.Join('.', parts);

        var deviceBody = new Dictionary<string, string>
        {
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic
        };
        var deviceResult = await _fx.Request(IdentityEndpoints.Device, deviceBody);
        var deviceResponse = deviceResult.Should().BeOfType<Dictionary<string, object?>>().Subject;
        var userCode = deviceResponse["user_code"]!.ToString()!;

        var verifyBody = new Dictionary<string, string>
        {
            ["user_code"] = userCode
        };
        var verifyExchange = await _fx.RequestWithHeaders(
            IdentityEndpoints.Verification,
            verifyBody,
            new Dictionary<string, object?>
            {
                ["access_token"] = tampered
            });

        var verifyResponse = (verifyExchange.Out?.Body as Dictionary<string, object?>)!;
        verifyResponse.Should().NotBeNull();
        verifyResponse.Should().ContainKey("error");
        verifyResponse["error"].Should().Be("login_required",
            because: "a tampered signature must NOT authenticate the user — " +
                    "bearer validation rejects it and (with no form creds) the handler asks for login");
    }
}
