using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Services;
using redb.Identity.Resource.Dpop;
using Xunit;

namespace redb.Identity.Tests.Dpop;

/// <summary>
/// Z4 P2.3 (RFC 9449 §7): unit tests for the Resource-Server side DPoP-bound access token validator.
/// </summary>
public class DpopResourceTokenValidatorTests
{
    private const string ResourceUrl = "https://api.test/protected";

    [Fact]
    public async Task Valid_Proof_With_Matching_Cnf_Jkt_And_Ath_Validates()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jkt = ComputeJkt(ec);
        var accessToken = BuildAccessToken(cnfJkt: jkt);
        var ath = DpopResourceTokenValidator.ComputeAth(accessToken);
        var proof = BuildProof(ec, "GET", ResourceUrl, ath: ath);

        var sut = BuildSut();
        var result = await sut.ValidateAsync(accessToken, proof, "GET", ResourceUrl);

        result.IsValid.Should().BeTrue("proof's jkt matches cnf.jkt and ath matches the token hash");
        result.Jkt.Should().Be(jkt);
    }

    [Fact]
    public async Task Mismatching_Jkt_Fails_With_InvalidToken()
    {
        using var keyForToken = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var keyForProof = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var accessToken = BuildAccessToken(cnfJkt: ComputeJkt(keyForToken));
        var ath = DpopResourceTokenValidator.ComputeAth(accessToken);
        var proof = BuildProof(keyForProof, "GET", ResourceUrl, ath: ath);

        var sut = BuildSut();
        var result = await sut.ValidateAsync(accessToken, proof, "GET", ResourceUrl);

        result.IsValid.Should().BeFalse();
        result.Error.Should().Be("invalid_token");
        result.ErrorDescription.Should().Contain("cnf.jkt");
    }

    [Fact]
    public async Task Wrong_Ath_Fails_With_InvalidDpopProof()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var accessToken = BuildAccessToken(cnfJkt: ComputeJkt(ec));
        var proof = BuildProof(ec, "GET", ResourceUrl, ath: "wrong-ath-value-not-the-real-hash-aaaaaa");

        var sut = BuildSut();
        var result = await sut.ValidateAsync(accessToken, proof, "GET", ResourceUrl);

        result.IsValid.Should().BeFalse();
        result.Error.Should().Be("invalid_dpop_proof");
    }

    [Fact]
    public async Task AccessToken_Without_Cnf_Claim_Fails()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var accessToken = BuildAccessToken(cnfJkt: null);
        var ath = DpopResourceTokenValidator.ComputeAth(accessToken);
        var proof = BuildProof(ec, "GET", ResourceUrl, ath: ath);

        var sut = BuildSut();
        var result = await sut.ValidateAsync(accessToken, proof, "GET", ResourceUrl);

        result.IsValid.Should().BeFalse();
        result.Error.Should().Be("invalid_token");
        result.ErrorDescription.Should().Contain("cnf.jkt");
    }

    [Fact]
    public void BuildChallengeHeader_Produces_Valid_Format()
    {
        var header = DpopResourceTokenValidator.BuildChallengeHeader(
            error: "invalid_token",
            errorDescription: "missing proof",
            allowedAlgs: "ES256 RS256",
            nonce: "abc123");

        header.Should().StartWith("DPoP ");
        header.Should().Contain("error=\"invalid_token\"");
        header.Should().Contain("error_description=\"missing proof\"");
        header.Should().Contain("algs=\"ES256 RS256\"");
        header.Should().Contain("nonce=\"abc123\"");
    }

    [Fact]
    public void ComputeAth_Matches_Rfc_9449_Spec()
    {
        // Sample from RFC 9449 §4.2 example.
        var token = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(token));
        var expected = Base64UrlEncoder.Encode(hash);
        DpopResourceTokenValidator.ComputeAth(token).Should().Be(expected);
    }

    // ─── helpers ───

    private static DpopResourceTokenValidator BuildSut()
    {
        var opts = Microsoft.Extensions.Options.Options.Create(new RedbIdentityOptions
        {
            Issuer = new Uri("https://identity.test/"),
            Dpop = new DpopOptions
            {
                Enabled = true,
                IatToleranceSeconds = 60,
            }
        });
        var replayStore = new MemoryDpopReplayStore(TimeProvider.System, null);
        var validator = new DpopProofValidator(
            replayStore,
            opts,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<DpopProofValidator>.Instance);
        return new DpopResourceTokenValidator(validator);
    }

    /// <summary>
    /// Builds an unsigned-but-readable JWT (alg=none) suitable for the validator's
    /// payload-only inspection (it does not re-validate signature on access token).
    /// </summary>
    private static string BuildAccessToken(string? cnfJkt)
    {
        var header = "{\"alg\":\"none\",\"typ\":\"at+jwt\"}";
        string payload;
        if (cnfJkt is not null)
            payload = $"{{\"sub\":\"alice\",\"cnf\":{{\"jkt\":\"{cnfJkt}\"}},\"iat\":{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}}}";
        else
            payload = $"{{\"sub\":\"alice\",\"iat\":{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}}}";
        var headerB64 = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header));
        var payloadB64 = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload));
        return $"{headerB64}.{payloadB64}.";
    }

    private static string BuildProof(ECDsa ec, string method, string url, string? ath = null)
    {
        var pubParams = ec.ExportParameters(includePrivateParameters: false);
        var x = Base64UrlEncoder.Encode(pubParams.Q.X!);
        var y = Base64UrlEncoder.Encode(pubParams.Q.Y!);
        var jwk = $"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}";
        var header = $"{{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":{jwk}}}";
        var iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var jti = Guid.NewGuid().ToString("N");
        string payload;
        if (ath is not null)
            payload = $"{{\"htm\":\"{method}\",\"htu\":\"{url}\",\"iat\":{iat},\"jti\":\"{jti}\",\"ath\":\"{ath}\"}}";
        else
            payload = $"{{\"htm\":\"{method}\",\"htu\":\"{url}\",\"iat\":{iat},\"jti\":\"{jti}\"}}";

        var hB64 = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header));
        var pB64 = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload));
        var signingInput = $"{hB64}.{pB64}";
        var sig = ec.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256);
        return $"{signingInput}.{Base64UrlEncoder.Encode(sig)}";
    }

    private static string ComputeJkt(ECDsa ec)
    {
        var p = ec.ExportParameters(false);
        var x = Base64UrlEncoder.Encode(p.Q.X!);
        var y = Base64UrlEncoder.Encode(p.Q.Y!);
        var canonical = $"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}";
        return Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }
}
