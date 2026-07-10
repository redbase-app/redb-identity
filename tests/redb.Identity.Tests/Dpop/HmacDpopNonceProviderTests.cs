using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Tokens;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Services;
using redb.Identity.Resource.Dpop;
using Xunit;

namespace redb.Identity.Tests.Dpop;

/// <summary>
/// Z4 P2 (RFC 9449 §8): unit tests for the stateless HMAC nonce provider used to sign
/// DPoP-Nonce challenges.
/// </summary>
public class HmacDpopNonceProviderTests
{
    private static (HmacDpopNonceProvider provider, FakeTimeProvider time) BuildSut(TimeSpan? lifetime = null)
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var opts = Options.Create(new RedbIdentityOptions
        {
            Issuer = new Uri("https://identity.test/"),
            Dpop = new DpopOptions
            {
                Enabled = true,
                NonceLifetime = lifetime ?? TimeSpan.FromMinutes(5),
                NonceSigningSecret = "test-secret-fixed-for-determinism"
            }
        });
        return (new HmacDpopNonceProvider(opts, time), time);
    }

    [Fact]
    public void IssueNonce_Round_Trip_Validates_True()
    {
        var (sut, _) = BuildSut();
        var nonce = sut.IssueNonce();
        nonce.Should().NotBeNullOrEmpty();
        sut.ValidateNonce(nonce).Should().BeTrue("a freshly issued nonce must validate");
    }

    [Fact]
    public void ValidateNonce_After_Lifetime_Expires_Returns_False()
    {
        var (sut, time) = BuildSut(lifetime: TimeSpan.FromSeconds(10));
        var nonce = sut.IssueNonce();
        time.Advance(TimeSpan.FromSeconds(11));
        sut.ValidateNonce(nonce).Should().BeFalse("RFC 9449 §8: expired nonce must be rejected");
    }

    [Fact]
    public void ValidateNonce_Tampered_Mac_Returns_False()
    {
        var (sut, _) = BuildSut();
        var nonce = sut.IssueNonce();
        var bytes = Base64UrlEncoder.DecodeBytes(nonce);
        bytes[^1] ^= 0x01; // flip a bit in the MAC
        var tampered = Base64UrlEncoder.Encode(bytes);
        sut.ValidateNonce(tampered).Should().BeFalse("HMAC-tampered nonce must not validate");
    }

    [Fact]
    public void ValidateNonce_Different_Secret_Returns_False()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var optsA = Options.Create(new RedbIdentityOptions
        {
            Issuer = new Uri("https://identity.test/"),
            Dpop = new DpopOptions { Enabled = true, NonceSigningSecret = "secret-A" }
        });
        var optsB = Options.Create(new RedbIdentityOptions
        {
            Issuer = new Uri("https://identity.test/"),
            Dpop = new DpopOptions { Enabled = true, NonceSigningSecret = "secret-B" }
        });
        var providerA = new HmacDpopNonceProvider(optsA, time);
        var providerB = new HmacDpopNonceProvider(optsB, time);

        var nonceA = providerA.IssueNonce();
        providerB.ValidateNonce(nonceA).Should().BeFalse(
            "nonces signed with secret-A must not validate against provider with secret-B");
    }

    [Fact]
    public void ValidateNonce_Empty_Or_Garbage_Returns_False()
    {
        var (sut, _) = BuildSut();
        sut.ValidateNonce("").Should().BeFalse();
        sut.ValidateNonce("not-base64url!").Should().BeFalse();
        sut.ValidateNonce("AAAA").Should().BeFalse("payload too short");
    }
}
