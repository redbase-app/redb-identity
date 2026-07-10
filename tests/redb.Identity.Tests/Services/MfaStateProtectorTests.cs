using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using Xunit;

namespace redb.Identity.Tests.Services;

/// <summary>
/// Unit tests for <see cref="MfaStateProtector"/>:
/// DataProtection-based state encrypt/decrypt with TTL validation.
/// No PostgreSQL required — ephemeral key ring only.
/// </summary>
public sealed class MfaStateProtectorTests
{
    private static MfaStateProtector CreateProtector()
    {
        var dpProvider = DataProtectionProvider.Create("redb-identity-tests");
        return new MfaStateProtector(dpProvider);
    }

    [Fact]
    public void Protect_Unprotect_RoundTrip()
    {
        var protector = CreateProtector();
        var state = new MfaState
        {
            UserId = 42,
            Username = "alice",
            Methods = ["totp"],
            ReturnUrl = "/dashboard"
        };

        var encrypted = protector.Protect(state);
        encrypted.Should().NotBeNullOrEmpty();

        var restored = protector.Unprotect(encrypted);
        restored.Should().NotBeNull();
        restored!.UserId.Should().Be(42);
        restored.Username.Should().Be("alice");
        restored.Methods.Should().BeEquivalentTo(["totp"]);
        restored.ReturnUrl.Should().Be("/dashboard");
        restored.IssuedAt.Should().NotBeNull("Protect must set IssuedAt if missing");
    }

    [Fact]
    public void Protect_SetsIssuedAt_WhenMissing()
    {
        var protector = CreateProtector();
        var state = new MfaState { UserId = 1, Username = "test" };

        var before = DateTimeOffset.UtcNow;
        var encrypted = protector.Protect(state);
        var after = DateTimeOffset.UtcNow;

        var restored = protector.Unprotect(encrypted);
        restored.Should().NotBeNull();
        restored!.IssuedAt.Should().BeOnOrAfter(before);
        restored.IssuedAt.Should().BeOnOrBefore(after);
    }

    [Fact]
    public void Protect_PreservesExistingIssuedAt()
    {
        var protector = CreateProtector();
        var fixedTime = DateTimeOffset.UtcNow.AddMinutes(-1);
        var state = new MfaState
        {
            UserId = 1,
            Username = "test",
            IssuedAt = fixedTime
        };

        var encrypted = protector.Protect(state);
        var restored = protector.Unprotect(encrypted);

        restored.Should().NotBeNull();
        restored!.IssuedAt!.Value.Should().BeCloseTo(fixedTime, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public void Unprotect_ExpiredState_ReturnsNull()
    {
        var protector = CreateProtector();
        var state = new MfaState
        {
            UserId = 1,
            Username = "test",
            IssuedAt = DateTimeOffset.UtcNow.AddMinutes(-10)
        };

        var encrypted = protector.Protect(state);

        // Default max age is 5 minutes — state issued 10 minutes ago should be expired
        var result = protector.Unprotect(encrypted);
        result.Should().BeNull("state is older than 5-minute default TTL");
    }

    [Fact]
    public void Unprotect_CustomMaxAge_Respected()
    {
        var protector = CreateProtector();
        var state = new MfaState
        {
            UserId = 1,
            Username = "test",
            IssuedAt = DateTimeOffset.UtcNow.AddSeconds(-30)
        };

        var encrypted = protector.Protect(state);

        // 10-second max age → expired
        var result1 = protector.Unprotect(encrypted, maxAge: TimeSpan.FromSeconds(10));
        result1.Should().BeNull("state is older than custom 10-second TTL");

        // 60-second max age → valid
        var result2 = protector.Unprotect(encrypted, maxAge: TimeSpan.FromSeconds(60));
        result2.Should().NotBeNull("state is within custom 60-second TTL");
    }

    [Fact]
    public void Unprotect_NullOrEmpty_ReturnsNull()
    {
        var protector = CreateProtector();

        protector.Unprotect(null!).Should().BeNull();
        protector.Unprotect("").Should().BeNull();
    }

    [Fact]
    public void Unprotect_TamperedData_ReturnsNull()
    {
        var protector = CreateProtector();
        var state = new MfaState { UserId = 1, Username = "test" };
        var encrypted = protector.Protect(state);

        var chars = encrypted.ToCharArray();
        chars[encrypted.Length / 2] = (char)(chars[encrypted.Length / 2] ^ 0xFF);
        var tampered = new string(chars);

        protector.Unprotect(tampered).Should().BeNull("tampered data must be rejected");
    }

    [Fact]
    public void Unprotect_GarbageInput_ReturnsNull()
    {
        var protector = CreateProtector();
        protector.Unprotect("not-valid-base64!!!").Should().BeNull();
        protector.Unprotect("AAAA").Should().BeNull();
    }

    [Fact]
    public void Unprotect_InvalidUserId_ReturnsNull()
    {
        var protector = CreateProtector();
        var state = new MfaState
        {
            UserId = 0, // invalid
            Username = "test"
        };

        var encrypted = protector.Protect(state);
        var result = protector.Unprotect(encrypted);
        result.Should().BeNull("userId <= 0 should be rejected");
    }

    /// <summary>
    /// G5 — Two <c>Protect</c> calls with identical inputs MUST produce different ciphertexts
    /// (non-deterministic AEAD via DataProtection). Otherwise an attacker observing repeated
    /// state cookies could correlate sessions purely from the wire.
    /// </summary>
    [Fact]
    public void Protect_IsNonDeterministic_AcrossCalls()
    {
        var protector = CreateProtector();
        var fixedTime = DateTimeOffset.UtcNow;
        var state = new MfaState
        {
            UserId = 42,
            Username = "alice",
            IssuedAt = fixedTime, // pin to remove the only legitimate source of variance
            Jti = Guid.Parse("11111111-1111-1111-1111-111111111111"),
        };

        var first = protector.Protect(state);
        var second = protector.Protect(state);

        first.Should().NotBe(second,
            "DataProtection uses a fresh nonce per Protect() call — identical plaintexts must yield distinct ciphertexts");
        // Both must still round-trip to the same logical state.
        protector.Unprotect(first)!.UserId.Should().Be(42);
        protector.Unprotect(second)!.UserId.Should().Be(42);
    }
}
