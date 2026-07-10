using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using OpenIddict.Server;
using redb.Identity.Core.Services;
using Xunit;

namespace redb.Identity.Tests.Services;

/// <summary>
/// Unit tests for <see cref="LogoutTokenBuilder"/> — verifies OIDC Back-Channel Logout 1.0
/// §2.4 conformance: required claims, signature, and absence of <c>nonce</c>.
/// </summary>
public sealed class LogoutTokenBuilderTests
{
    private static readonly JwtSecurityTokenHandler _handler = new() { MapInboundClaims = false };

    private static (LogoutTokenBuilder builder, SecurityKey key, FakeTimeProvider time)
        CreateBuilder(string issuer = "https://idp.example.com")
    {
        using var rsa = RSA.Create(2048);
        var key = new RsaSecurityKey(rsa.ExportParameters(true)) { KeyId = "test-rsa" };
        var creds = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);

        var serverOptions = new OpenIddictServerOptions
        {
            Issuer = new Uri(issuer)
        };
        serverOptions.SigningCredentials.Add(creds);

        var monitor = Substitute.For<IOptionsMonitor<OpenIddictServerOptions>>();
        monitor.CurrentValue.Returns(serverOptions);

        var time = new FakeTimeProvider(new DateTimeOffset(2026, 5, 1, 12, 0, 0, TimeSpan.Zero));
        return (new LogoutTokenBuilder(monitor, time), key, time);
    }

    [Fact]
    public void Build_ContainsAllRequiredClaims()
    {
        var (builder, _, time) = CreateBuilder();

        var token = builder.Build("client-abc", "user-42", sessionId: "sess-7");
        token.Should().NotBeNull();

        var jwt = _handler.ReadJwtToken(token);
        jwt.Issuer.Should().Be("https://idp.example.com");
        jwt.Audiences.Should().ContainSingle().Which.Should().Be("client-abc");
        jwt.Payload["sub"].Should().Be("user-42");
        jwt.Payload["sid"].Should().Be("sess-7");
        jwt.Payload.ContainsKey("jti").Should().BeTrue();
        ((long)jwt.Payload["iat"]).Should().Be(time.GetUtcNow().ToUnixTimeSeconds());

        // events claim is required
        jwt.Payload.ContainsKey("events").Should().BeTrue();
        var events = jwt.Payload["events"]!.ToString()!;
        events.Should().Contain("http://schemas.openid.net/event/backchannel-logout");
    }

    [Fact]
    public void Build_DoesNotIncludeNonce()
    {
        var (builder, _, _) = CreateBuilder();
        var token = builder.Build("client-x", "user-1");
        var jwt = _handler.ReadJwtToken(token);

        // Spec §2.4: logout_token MUST NOT contain nonce.
        jwt.Payload.ContainsKey("nonce").Should().BeFalse();
    }

    [Fact]
    public void Build_OmitsSid_WhenNotProvided()
    {
        var (builder, _, _) = CreateBuilder();
        var token = builder.Build("client-x", "user-1");
        var jwt = _handler.ReadJwtToken(token);
        jwt.Payload.ContainsKey("sid").Should().BeFalse();
    }

    [Fact]
    public void Build_SignatureVerifiesUnderConfiguredKey()
    {
        var (builder, key, _) = CreateBuilder();

        var token = builder.Build("client-x", "user-1");

        var validation = new TokenValidationParameters
        {
            ValidIssuer = "https://idp.example.com",
            ValidateIssuer = true,
            ValidAudience = "client-x",
            ValidateAudience = true,
            ValidateLifetime = false, // logout_token has no exp
            IssuerSigningKey = key,
            ValidateIssuerSigningKey = true
        };

        var result = _handler.ValidateToken(token, validation, out _);
        result.Identity!.IsAuthenticated.Should().BeTrue();
    }

    [Fact]
    public void Build_EachCallEmitsUniqueJti()
    {
        var (builder, _, _) = CreateBuilder();
        var t1 = builder.Build("client-x", "user-1");
        var t2 = builder.Build("client-x", "user-1");

        var j1 = _handler.ReadJwtToken(t1).Payload["jti"]!.ToString();
        var j2 = _handler.ReadJwtToken(t2).Payload["jti"]!.ToString();
        j1.Should().NotBe(j2);
    }

    [Fact]
    public void Build_ReturnsNull_WhenNoSigningKey()
    {
        var serverOptions = new OpenIddictServerOptions { Issuer = new Uri("https://idp.example.com") };
        var monitor = Substitute.For<IOptionsMonitor<OpenIddictServerOptions>>();
        monitor.CurrentValue.Returns(serverOptions);
        var builder = new LogoutTokenBuilder(monitor);

        builder.CanIssue.Should().BeFalse();
        builder.Build("client-x", "user-1").Should().BeNull();
    }

    [Fact]
    public void Build_EventsClaim_IsValidJsonObject()
    {
        var (builder, _, _) = CreateBuilder();
        var token = builder.Build("client-x", "user-1");

        // Decode payload manually to ensure events serialised as a real JSON object,
        // not a stringified value (RPs parse logout_token as standard JWT JSON).
        var payloadSegment = token!.Split('.')[1];
        // Pad base64url
        payloadSegment = payloadSegment.PadRight(payloadSegment.Length + (4 - payloadSegment.Length % 4) % 4, '=')
            .Replace('-', '+').Replace('_', '/');
        var json = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(payloadSegment));

        using var doc = JsonDocument.Parse(json);
        var events = doc.RootElement.GetProperty("events");
        events.ValueKind.Should().Be(JsonValueKind.Object);
        events.GetProperty("http://schemas.openid.net/event/backchannel-logout").ValueKind
            .Should().Be(JsonValueKind.Object);
    }
}
