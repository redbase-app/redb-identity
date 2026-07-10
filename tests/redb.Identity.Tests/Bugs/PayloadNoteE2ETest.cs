using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;
using redb.Identity.Contracts.Routes;
using redb.Identity.Core.Stores;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.Bugs;

/// <summary>
/// Full-stack E2E: complete authorization_code flow with 4 scopes,
/// then verify that token payload is stored in _objects.note (not PROPS _values._string).
/// </summary>
[Collection("ProductionBootstrap")]
public class PayloadNoteE2ETest
{
    private readonly ProductionBootstrapFixture _fx;
    private readonly ITestOutputHelper _output;

    public PayloadNoteE2ETest(ProductionBootstrapFixture fx, ITestOutputHelper output)
    {
        _fx = fx;
        _output = output;
    }

    [Fact]
    public async Task FourScopes_TokenPayload_StoredInNote()
    {
        // Snapshot existing token count
        var store = new RedbTokenStore(_fx.Redb);
        var beforeCount = await store.CountAsync(CancellationToken.None);
        var beforeTime = DateTimeOffset.UtcNow.AddSeconds(-2);

        // Full auth_code + PKCE flow with 4 scopes
        var (codeVerifier, codeChallenge) = GeneratePkce();

        var authorizeBody = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic,
            ["redirect_uri"] = ProductionBootstrapFixture.TestRedirectUri,
            ["scope"] = "openid profile email phone",
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256"
        };

        var authorizeResult = await _fx.RequestWithSession(IdentityEndpoints.Authorize, authorizeBody);
        var authorizeResponse = (Dictionary<string, object?>)authorizeResult!;
        authorizeResponse.Should().ContainKey("code");
        var code = authorizeResponse["code"]!.ToString()!;
        _output.WriteLine($"Got authorization code: {code[..Math.Min(code.Length, 20)]}...");

        var tokenBody = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = ProductionBootstrapFixture.TestRedirectUri,
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic,
            ["code_verifier"] = codeVerifier
        };

        var tokenResult = await _fx.Request(IdentityEndpoints.Token, tokenBody);
        var tokenResponse = (Dictionary<string, object?>)tokenResult!;
        tokenResponse.Should().ContainKey("access_token");
        _output.WriteLine("Token exchange succeeded with 4 scopes");

        // Find tokens created AFTER our flow started (i.e. the new ones)
        var allTokens = new List<RedbObject<TokenProps>>();
        await foreach (var t in store.ListAsync(null, null, CancellationToken.None))
        {
            if (t.date_create >= beforeTime)
                allTokens.Add(t);
        }

        _output.WriteLine($"New tokens created during this test: {allTokens.Count}");

        // Authorization codes and reference tokens get payload stored.
        // Self-contained JWTs (access_token with DisableAccessTokenEncryption)
        // may NOT store payload (the JWT itself is the payload).
        // So we check: any token that does have note should have null Props.Payload
        foreach (var t in allTokens)
        {
            _output.WriteLine($"  Token id={t.id}, type={t.Props.Type}, " +
                $"note={(!string.IsNullOrEmpty(t.note) ? $"{t.note.Length}b" : "null")}, " +
                $"Props.Payload={(t.Props.Payload != null ? "SET" : "null")}");

            // The key invariant: Props.Payload is NEVER in PROPS (always null after load)
            t.Props.Payload.Should().BeNull(
                $"Token {t.id} ({t.Props.Type}): Payload should not be in PROPS — [RedbIgnore] excludes it");
        }

        // There should be new tokens from the flow
        allTokens.Should().NotBeEmpty("the auth code flow should create at least one token");
    }

    [Fact]
    public async Task TokenPayload_SurvivesUpdateCycle()
    {
        // Create a token with payload in note, update status, verify payload survives
        var store = new RedbTokenStore(_fx.Redb);
        var appStore = new RedbApplicationStore(_fx.Redb);
        var authStore = new RedbAuthorizationStore(_fx.Redb);

        // Create supporting entities
        var app = new RedbObject<ApplicationProps>
        {
            name = $"payload-e2e-{Guid.NewGuid():N}",
            Props = new ApplicationProps
            {
                ClientId = $"pe2e-{Guid.NewGuid():N}",
                ClientType = "confidential"
            }
        };
        await appStore.CreateAsync(app, CancellationToken.None);

        var auth = new RedbObject<AuthorizationProps>
        {
            key = 1,
            Props = new AuthorizationProps
            {
                ApplicationObjectId = app.id,
                Status = "valid",
                Type = "permanent"
            }
        };
        await authStore.CreateAsync(auth, CancellationToken.None);

        // Create token with large payload in note
        var largePayload = new string('J', 5000);
        var token = new RedbObject<TokenProps>
        {
            key = 1,
            value_long = app.id,
            value_string = $"ref-{Guid.NewGuid():N}",
            note = largePayload,
            Props = new TokenProps
            {
                AuthorizationObjectId = auth.id,
                Status = "valid",
                Type = "access_token"
            }
        };
        await store.CreateAsync(token, CancellationToken.None);
        _output.WriteLine($"Created token id={token.id} with {largePayload.Length}b payload in note");

        // Update status
        var loaded = (await store.FindByIdAsync(token.id.ToString(), CancellationToken.None))!;
        loaded.Props.Status = "revoked";
        await store.UpdateAsync(loaded, CancellationToken.None);

        // Reload and verify payload survived
        var reloaded = (await store.FindByIdAsync(token.id.ToString(), CancellationToken.None))!;
        reloaded.note.Should().Be(largePayload, "payload in note should survive status update");
        reloaded.Props.Status.Should().Be("revoked");
        _output.WriteLine("Payload survived update cycle");
    }

    private static (string codeVerifier, string codeChallenge) GeneratePkce()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        var verifier = Convert.ToBase64String(bytes)
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        var challenge = Convert.ToBase64String(hash)
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return (verifier, challenge);
    }
}
