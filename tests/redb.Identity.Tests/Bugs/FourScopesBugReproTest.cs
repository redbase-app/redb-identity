using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using redb.Identity.Contracts.Routes;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.Bugs;

/// <summary>
/// Reproduction test for the 4-scopes bug:
/// "openid profile email phone" together → DbException.
/// </summary>
[Collection("ProductionBootstrap")]
public class FourScopesBugReproTest
{
    private readonly ProductionBootstrapFixture _fx;
    private readonly ITestOutputHelper _output;

    public FourScopesBugReproTest(ProductionBootstrapFixture fx, ITestOutputHelper output)
    {
        _fx = fx;
        _output = output;
    }

    [Fact]
    public async Task AuthCode_WithFourScopes_ShouldNotCrash()
    {
        // This is the exact scope combination that causes the DbException
        var scopes = "openid profile email phone";

        try
        {
            var accessToken = await ObtainAccessToken(scopes);
            _output.WriteLine($"SUCCESS: Got access token with 4 scopes: {accessToken[..20]}...");
            accessToken.Should().NotBeNullOrEmpty();
        }
        catch (Exception ex)
        {
            // Log the FULL exception tree so we can see the root cause
            _output.WriteLine("=== EXCEPTION CAUGHT ===");
            var current = ex;
            int depth = 0;
            while (current != null)
            {
                _output.WriteLine($"--- Exception depth {depth} ---");
                _output.WriteLine($"Type: {current.GetType().FullName}");
                _output.WriteLine($"Message: {current.Message}");
                _output.WriteLine($"Stack: {current.StackTrace}");
                current = current.InnerException;
                depth++;
            }
            throw; // Re-throw to fail the test
        }
    }

    [Fact]
    public async Task AuthCode_WithThreeScopes_ShouldWork()
    {
        // Baseline: 3 scopes works fine
        var accessToken = await ObtainAccessToken("openid profile email");
        _output.WriteLine($"SUCCESS: Got access token with 3 scopes: {accessToken[..20]}...");
        accessToken.Should().NotBeNullOrEmpty();
    }

    private async Task<string> ObtainAccessToken(string scopes)
    {
        var (codeVerifier, codeChallenge) = GeneratePkce();

        var authorizeBody = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ProductionBootstrapFixture.TestClientIdPublic,
            ["redirect_uri"] = ProductionBootstrapFixture.TestRedirectUri,
            ["scope"] = scopes,
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256"
        };

        var authorizeResult = await _fx.RequestWithSession(IdentityEndpoints.Authorize, authorizeBody);
        var authorizeResponse = (Dictionary<string, object?>)authorizeResult!;

        _output.WriteLine($"Authorize response keys: [{string.Join(", ", authorizeResponse.Keys)}]");
        foreach (var kv in authorizeResponse)
            _output.WriteLine($"  {kv.Key} = {kv.Value}");

        authorizeResponse.Should().ContainKey("code",
            $"Authorize failed. Response: {string.Join(", ", authorizeResponse.Select(kv => $"{kv.Key}={kv.Value}"))}");

        var code = authorizeResponse["code"]!.ToString()!;

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

        _output.WriteLine($"Token response keys: [{string.Join(", ", tokenResponse.Keys)}]");
        foreach (var kv in tokenResponse)
            _output.WriteLine($"  {kv.Key} = {kv.Value?.ToString()?[..Math.Min(kv.Value?.ToString()?.Length ?? 0, 80)]}");

        tokenResponse.Should().ContainKey("access_token",
            $"Token exchange failed. Response: {string.Join(", ", tokenResponse.Select(kv => $"{kv.Key}={kv.Value}"))}");

        return tokenResponse["access_token"]!.ToString()!;
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
