using FluentAssertions;
using OpenIddict.Abstractions;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Core.Query;
using redb.Identity.Core.Models;
using redb.Identity.Contracts.Routes;
using redb.Identity.Tests.Infrastructure;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace redb.Identity.Tests.TokenFlow;

/// <summary>
/// C11 — authorization_code single-use, atomic consume (RFC 6749 §10.5).
/// Verifies that:
///   1. Exchanging the same code twice fails with invalid_grant.
///   2. On reuse, previously-issued tokens (chained via authorization) are revoked.
///   3. Concurrent (parallel) exchanges of the same code result in exactly one success.
/// Atomicity is provided by optimistic-concurrency on RedbObject.hash inside
/// RedbTokenStore.UpdateAsync (single OpenIddict redeem winner per code).
/// </summary>
[Collection("ProductionBootstrap")]
public class AuthorizationCodeSingleUseTests
{
    private readonly ProductionBootstrapFixture _fx;

    public AuthorizationCodeSingleUseTests(ProductionBootstrapFixture fx) => _fx = fx;

    [Fact]
    public async Task AuthorizationCode_SecondUse_Fails_InvalidGrant()
    {
        var (code, codeVerifier) = await ObtainAuthorizationCode();

        // First exchange — succeeds.
        var first = await ExchangeCode(code, codeVerifier);
        first.Should().ContainKey("access_token", "first code exchange must succeed");
        first.Should().NotContainKey("error");

        // Second exchange of the SAME code — must be rejected.
        var second = await ExchangeCode(code, codeVerifier);
        second.Should().ContainKey("error", "code is single-use");
        second["error"]!.ToString().Should().BeOneOf(
            OpenIddictConstants.Errors.InvalidGrant,
            OpenIddictConstants.Errors.InvalidToken);
    }

    [Fact]
    public async Task AuthorizationCode_SecondUse_RevokesPreviouslyIssuedTokens()
    {
        var (code, codeVerifier) = await ObtainAuthorizationCode();

        // First exchange — issues access_token (+ refresh_token if offline_access).
        var first = await ExchangeCode(code, codeVerifier);
        first.Should().ContainKey("access_token");
        var refreshToken = first.GetValueOrDefault("refresh_token")?.ToString();

        // Snapshot Valid token entries linked to the public subject GUID BEFORE replay.
        var validBefore = await CountValidTokensForSubject(_fx.TestSubjectGuid);
        validBefore.Should().BeGreaterThan(0, "first exchange must persist at least one Valid token entry");

        // Replay the same code — OpenIddict must detect reuse and revoke the chained tokens.
        var second = await ExchangeCode(code, codeVerifier);
        second.Should().ContainKey("error");
        second["error"]!.ToString().Should().BeOneOf(
            OpenIddictConstants.Errors.InvalidGrant,
            OpenIddictConstants.Errors.InvalidToken);

        // Allow OpenIddict's chained-revoke pass to flush.
        var validAfter = await CountValidTokensForSubject(_fx.TestSubjectGuid);
        validAfter.Should().BeLessThan(validBefore,
            "OpenIddict must revoke tokens chained to the reused authorization code");

        // If we got a refresh token, it must now be unusable.
        if (!string.IsNullOrEmpty(refreshToken))
        {
            var refreshBody = new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken,
                ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic
            };
            var refreshResult = await _fx.Request(IdentityEndpoints.Token, refreshBody);
            var refreshResponse = (Dictionary<string, object?>)refreshResult!;
            refreshResponse.Should().ContainKey("error",
                "refresh token chained to a reused auth code must be revoked");
        }
    }

    [Fact]
    public async Task AuthorizationCode_ConcurrentExchanges_ExactlyOneSucceeds()
    {
        const int Parallelism = 16;
        var (code, codeVerifier) = await ObtainAuthorizationCode();

        var tasks = Enumerable.Range(0, Parallelism)
            .Select(_ => ExchangeCode(code, codeVerifier))
            .ToArray();

        var results = await Task.WhenAll(tasks);

        var successCount = results.Count(r => r.ContainsKey("access_token") && !r.ContainsKey("error"));
        var errorCount = results.Count(r => r.ContainsKey("error"));

        successCount.Should().Be(1,
            "atomic single-use: exactly one parallel exchange may succeed " +
            $"(success={successCount}, error={errorCount})");
        errorCount.Should().Be(Parallelism - 1);

        // All errors must be invalid_grant or invalid_token (not 500/internal-error).
        foreach (var r in results.Where(x => x.ContainsKey("error")))
        {
            r["error"]!.ToString().Should().BeOneOf(
                OpenIddictConstants.Errors.InvalidGrant,
                OpenIddictConstants.Errors.InvalidToken);
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private async Task<(string code, string codeVerifier)> ObtainAuthorizationCode()
    {
        var (codeVerifier, codeChallenge) = GeneratePkce();

        var authorizeBody = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic,
            ["redirect_uri"] = ProductionBootstrapFixture.TestRedirectUri,
            ["scope"] = "openid offline_access",
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256"
        };

        var authorizeResult = await _fx.RequestWithSession(IdentityEndpoints.Authorize, authorizeBody);
        var authorizeResponse = (Dictionary<string, object?>)authorizeResult!;
        authorizeResponse.Should().ContainKey("code", "authorize must return a code");
        return (authorizeResponse["code"]!.ToString()!, codeVerifier);
    }

    private async Task<Dictionary<string, object?>> ExchangeCode(string code, string codeVerifier)
    {
        var body = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = ProductionBootstrapFixture.TestRedirectUri,
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic,
            ["code_verifier"] = codeVerifier
        };

        var result = await _fx.Request(IdentityEndpoints.Token, body);
        return (Dictionary<string, object?>)result!;
    }

    private async Task<int> CountValidTokensForSubject(Guid subjectGuid)
    {
        var tokens = await _fx.Redb.Query<TokenProps>()
            .WhereRedb(o => o.ValueGuid == subjectGuid)
            .Where(t => t.Status == OpenIddictConstants.Statuses.Valid)
            .ToListAsync();
        return tokens.Count;
    }

    private static (string codeVerifier, string codeChallenge) GeneratePkce()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        var verifier = Convert.ToBase64String(bytes)
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        var challenge = Convert.ToBase64String(hash)
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        return (verifier, challenge);
    }
}
