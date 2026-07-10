using System.Net;
using System.Text.Json;
using FluentAssertions;
using Microsoft.IdentityModel.JsonWebTokens;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// Full-stack E2E regression tests for H5 (v1.0 DoD §5): declarative ClaimMappers must
/// flow through the real OpenIddict <c>ProcessSignInContext</c> pipeline and end up
/// in the issued <c>access_token</c> JWT.
/// <para>
/// These tests also guard against the order-bug discovered during B0.1 work: the
/// <c>AttachClaimMapperClaims</c> handler was scheduled at <c>int.MaxValue - 200_000</c>,
/// AFTER the built-in <c>Exchange.ApplyTokenResponse&lt;ProcessSignInContext&gt;</c>
/// (fixed order 500_000) had already short-circuited the dispatcher via
/// <c>IsRequestHandled</c>. Result: ClaimMappers were silently dropped from every issued
/// token in production. Existing unit tests called the resolver directly and missed it.
/// Pre-existing unit tests in <c>ClaimMappersIntegrationTests</c> remain valuable but
/// only cover the resolver in isolation.
/// </para>
/// <para>
/// Each test uses a unique <c>claim_type</c> suffix to avoid cross-test contamination.
/// </para>
/// </summary>
[Collection("ProductionHttp")]
public class FullStackClaimMappersTests
{
    private readonly ProductionHttpFixture _fx;

    public FullStackClaimMappersTests(ProductionHttpFixture fx) => _fx = fx;

    [Fact]
    public async Task GlobalConstantMapper_AppearsInAccessToken()
    {
        var claimType = $"e2e_global_{Guid.NewGuid():N}".Substring(0, 32);
        const string constantValue = "engineering";

        await _fx.UseRedbAsync(redb => SeedGlobalMapper(
            redb,
            claimType,
            sourceKind: "Constant",
            constantValue: constantValue,
            destinations: new[] { "access_token" }));

        var token = await IssuePasswordToken("openid profile");

        var claim = ReadClaim(token, claimType);
        claim.Should().Be(constantValue,
            "global Constant mapper must flow through the OpenIddict pipeline into the JWT access_token. " +
            "If this fails, AttachClaimMapperClaims is being skipped — verify it runs BEFORE order 500_000.");
    }

    [Fact]
    public async Task UserPropsMapper_ReadsGivenName_FromSeededAdmin()
    {
        // The admin user seeded by ProductionHttpFixture has UserProps.GivenName = "E2E".
        var claimType = $"e2e_given_{Guid.NewGuid():N}".Substring(0, 32);

        await _fx.UseRedbAsync(redb => SeedGlobalMapper(
            redb,
            claimType,
            sourceKind: "UserProps",
            sourcePath: "GivenName",
            destinations: new[] { "access_token" }));

        var token = await IssuePasswordToken("openid profile");

        var claim = ReadClaim(token, claimType);
        claim.Should().Be("E2E",
            "UserProps mapper must resolve the seeded GivenName into the access_token");
    }

    [Fact]
    public async Task ScopeFilteredMapper_OmittedWhenScopeNotRequested()
    {
        // Mapper requires scope "profile" — a request without it must NOT include the claim.
        var claimType = $"e2e_scoped_{Guid.NewGuid():N}".Substring(0, 32);

        await _fx.UseRedbAsync(redb => SeedGlobalMapper(
            redb,
            claimType,
            sourceKind: "Constant",
            constantValue: "should_not_appear",
            requiredScopes: new[] { "profile" },
            destinations: new[] { "access_token" }));

        // Issue token WITHOUT "profile" scope.
        var token = await IssuePasswordToken("openid");

        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(token);
        jwt.TryGetPayloadValue<string>(claimType, out _).Should().BeFalse(
            "scope-filtered mapper must be skipped when its RequiredScopes are not requested");
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  helpers
    // ─────────────────────────────────────────────────────────────────────────

    private async Task<string> IssuePasswordToken(string scope)
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = ProductionHttpFixture.TestUsername,
            ["password"] = ProductionHttpFixture.TestPassword,
            ["client_id"] = ProductionHttpFixture.TestClientId,
            ["client_secret"] = ProductionHttpFixture.TestClientSecret,
            ["scope"] = scope,
        });
        var resp = await _fx.Http.PostAsync("/connect/token", content);
        var body = await resp.Content.ReadAsStringAsync();
        resp.StatusCode.Should().Be(HttpStatusCode.OK,
            "token issuance must succeed for non-gated test scope: {0}", body);
        var json = JsonDocument.Parse(body).RootElement;
        return json.GetProperty("access_token").GetString()!;
    }

    private static string? ReadClaim(string accessToken, string claimType)
    {
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(accessToken);
        return jwt.TryGetPayloadValue<string>(claimType, out var value) ? value : null;
    }

    private static async Task SeedGlobalMapper(
        IRedbService redb,
        string claimType,
        string sourceKind,
        string? sourcePath = null,
        string? constantValue = null,
        string[]? requiredScopes = null,
        string[]? destinations = null,
        bool required = false,
        int order = 0)
    {
        var mapper = new RedbObject<ClaimMapperProps>(new ClaimMapperProps
        {
            ClaimType = claimType,
            SourceKind = sourceKind,
            SourcePath = sourcePath,
            ConstantValue = constantValue,
            RequiredScopes = requiredScopes,
            Destinations = destinations,
            Required = required,
            Order = order,
            Enabled = true,
        });
        mapper.Name = $"e2e:{sourceKind}->{claimType}";
        // parent_id null → global mapper (applied to every token)
        await redb.SaveAsync(mapper);
    }
}
