using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Time.Testing;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Services;
using Xunit;

namespace redb.Identity.Tests.Services;

/// <summary>
/// Unit tests for <see cref="FederationStateProtector"/>:
/// DataProtection-based state encrypt/decrypt with TTL validation.
/// No PostgreSQL required — ephemeral key ring only.
/// </summary>
public sealed class FederationStateProtectorTests
{
    private static FederationStateProtector CreateProtector()
    {
        var dpProvider = DataProtectionProvider.Create("redb-identity-tests");
        return new FederationStateProtector(dpProvider);
    }

    [Fact]
    public void Protect_Unprotect_RoundTrip()
    {
        var protector = CreateProtector();
        var state = new FederationState
        {
            ProviderId = "google",
            ReturnUrl = "/dashboard",
            Nonce = "test-nonce-123",
            CodeVerifier = "test-verifier-456"
        };

        var encrypted = protector.Protect(state);
        encrypted.Should().NotBeNullOrEmpty();

        var restored = protector.Unprotect(encrypted);
        restored.Should().NotBeNull();
        restored!.ProviderId.Should().Be("google");
        restored.ReturnUrl.Should().Be("/dashboard");
        restored.Nonce.Should().Be("test-nonce-123");
        restored.CodeVerifier.Should().Be("test-verifier-456");
        restored.IssuedAt.Should().NotBeNull("Protect must set IssuedAt if missing");
    }

    [Fact]
    public void Protect_SetsIssuedAt_WhenMissing()
    {
        var protector = CreateProtector();
        var state = new FederationState { ProviderId = "azure-ad" };

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
        // Use a recent timestamp (within default 5-min TTL) to avoid expiry
        var fixedTime = DateTimeOffset.UtcNow.AddMinutes(-1);
        var state = new FederationState
        {
            ProviderId = "test",
            IssuedAt = fixedTime
        };

        var encrypted = protector.Protect(state);
        var restored = protector.Unprotect(encrypted);

        restored.Should().NotBeNull();
        // ??= should NOT overwrite an existing value
        restored!.IssuedAt!.Value.Should().BeCloseTo(fixedTime, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public void Unprotect_ExpiredState_ReturnsNull()
    {
        var protector = CreateProtector();
        var state = new FederationState
        {
            ProviderId = "google",
            IssuedAt = DateTimeOffset.UtcNow.AddMinutes(-10)
        };

        var encrypted = protector.Protect(state);

        // Default max age is 5 minutes — state issued 10 minutes ago should be expired
        var result = protector.Unprotect(encrypted);
        result.Should().BeNull("state is older than 5-minute default TTL");
    }

    [Fact]
    public void Unprotect_CustomMaxAge_RespectedCorrectly()
    {
        var protector = CreateProtector();
        var state = new FederationState
        {
            ProviderId = "google",
            IssuedAt = DateTimeOffset.UtcNow.AddSeconds(-30)
        };

        var encrypted = protector.Protect(state);

        // 10-second max age → state issued 30s ago should be expired
        var result = protector.Unprotect(encrypted, maxAge: TimeSpan.FromSeconds(10));
        result.Should().BeNull("state is older than custom 10-second TTL");

        // 60-second max age → state issued 30s ago should be valid
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
        var state = new FederationState { ProviderId = "google" };
        var encrypted = protector.Protect(state);

        // Flip bits in the middle
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
    public void DifferentProtectorInstances_SameKeyRing_CanDecrypt()
    {
        var dpProvider = DataProtectionProvider.Create("redb-identity-tests-shared");
        var protector1 = new FederationStateProtector(dpProvider);
        var protector2 = new FederationStateProtector(dpProvider);

        var state = new FederationState
        {
            ProviderId = "azure-ad",
            ReturnUrl = "/admin"
        };

        var encrypted = protector1.Protect(state);
        var restored = protector2.Unprotect(encrypted);

        restored.Should().NotBeNull();
        restored!.ProviderId.Should().Be("azure-ad");
    }

    [Fact]
    public void Protect_DifferentStates_ProduceDifferentCiphertexts()
    {
        var protector = CreateProtector();

        var state1 = new FederationState { ProviderId = "provider-a", Nonce = "a" };
        var state2 = new FederationState { ProviderId = "provider-b", Nonce = "b" };

        var enc1 = protector.Protect(state1);
        var enc2 = protector.Protect(state2);

        enc1.Should().NotBe(enc2);
    }

    // ── C6 hardening ──

    [Fact]
    public void Protect_AssignsJti_WhenMissing()
    {
        var protector = CreateProtector();
        var state = new FederationState { ProviderId = "google" };

        protector.Protect(state);

        state.Jti.Should().NotBeNullOrEmpty();
        state.Jti!.Length.Should().BeGreaterThan(16);
    }

    [Fact]
    public void Protect_PreservesExistingJti()
    {
        var protector = CreateProtector();
        var existingJti = "preset-jti-1234567890";
        var state = new FederationState { ProviderId = "google", Jti = existingJti };

        protector.Protect(state);

        state.Jti.Should().Be(existingJti);
    }

    [Fact]
    public async Task UnprotectAsync_FreshState_ReturnsState()
    {
        var protector = CreateProtector();
        var state = new FederationState { ProviderId = "google", ReturnUrl = "/x" };
        var encrypted = protector.Protect(state);

        var (restored, failure) = await protector.UnprotectAsync(encrypted, bindingSecret: null);

        failure.Should().Be(FederationStateValidationFailure.None);
        restored.Should().NotBeNull();
        restored!.ProviderId.Should().Be("google");
    }

    [Fact]
    public async Task UnprotectAsync_OneTimeUse_RejectsSecondConsumption()
    {
        var fakeTime = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var nonceStore = new InMemoryFederationStateNonceStore(fakeTime);
        var protector = new FederationStateProtector(
            DataProtectionProvider.Create("redb-c6-tests"),
            fakeTime,
            nonceStore,
            new FederationStateOptions { RequireOneTimeUse = true });

        var encrypted = protector.Protect(new FederationState { ProviderId = "google" });

        var (s1, f1) = await protector.UnprotectAsync(encrypted, bindingSecret: null);
        f1.Should().Be(FederationStateValidationFailure.None);
        s1.Should().NotBeNull();

        var (s2, f2) = await protector.UnprotectAsync(encrypted, bindingSecret: null);
        f2.Should().Be(FederationStateValidationFailure.AlreadyUsed);
        s2.Should().BeNull();
    }

    [Fact]
    public async Task UnprotectAsync_BrowserBinding_RejectsMissingCookie()
    {
        var fakeTime = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var protector = new FederationStateProtector(
            DataProtectionProvider.Create("redb-c6-bind-1"),
            fakeTime,
            new InMemoryFederationStateNonceStore(fakeTime),
            new FederationStateOptions());

        var secret = "browser-secret-aaaa";
        var hash = FederationStateProtector.ComputeBindingHash(secret);
        var encrypted = protector.Protect(new FederationState { ProviderId = "google", BindingHash = hash });

        var (state, failure) = await protector.UnprotectAsync(encrypted, bindingSecret: null);

        failure.Should().Be(FederationStateValidationFailure.BindingMismatch);
        state.Should().BeNull();
    }

    [Fact]
    public async Task UnprotectAsync_BrowserBinding_RejectsWrongCookie()
    {
        var fakeTime = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var protector = new FederationStateProtector(
            DataProtectionProvider.Create("redb-c6-bind-2"),
            fakeTime,
            new InMemoryFederationStateNonceStore(fakeTime),
            new FederationStateOptions());

        var hash = FederationStateProtector.ComputeBindingHash("real-secret-xx");
        var encrypted = protector.Protect(new FederationState { ProviderId = "google", BindingHash = hash });

        var (state, failure) = await protector.UnprotectAsync(encrypted, bindingSecret: "attacker-secret");

        failure.Should().Be(FederationStateValidationFailure.BindingMismatch);
        state.Should().BeNull();
    }

    [Fact]
    public async Task UnprotectAsync_BrowserBinding_AcceptsMatchingCookie()
    {
        var fakeTime = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var protector = new FederationStateProtector(
            DataProtectionProvider.Create("redb-c6-bind-3"),
            fakeTime,
            new InMemoryFederationStateNonceStore(fakeTime),
            new FederationStateOptions());

        var secret = "matching-secret-zzz";
        var hash = FederationStateProtector.ComputeBindingHash(secret);
        var encrypted = protector.Protect(new FederationState { ProviderId = "google", BindingHash = hash });

        var (state, failure) = await protector.UnprotectAsync(encrypted, bindingSecret: secret);

        failure.Should().Be(FederationStateValidationFailure.None);
        state.Should().NotBeNull();
    }

    [Fact]
    public async Task UnprotectAsync_ExpiredAfterStateMaxAge_ReturnsExpired()
    {
        var fakeTime = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var protector = new FederationStateProtector(
            DataProtectionProvider.Create("redb-c6-ttl"),
            fakeTime,
            new InMemoryFederationStateNonceStore(fakeTime),
            new FederationStateOptions { StateMaxAge = TimeSpan.FromMinutes(1) });

        var encrypted = protector.Protect(new FederationState { ProviderId = "google" });

        fakeTime.Advance(TimeSpan.FromMinutes(2));

        var (state, failure) = await protector.UnprotectAsync(encrypted, bindingSecret: null);

        failure.Should().Be(FederationStateValidationFailure.Expired);
        state.Should().BeNull();
    }

    [Fact]
    public async Task UnprotectAsync_OneTimeUseDisabled_AllowsReplay()
    {
        var fakeTime = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var protector = new FederationStateProtector(
            DataProtectionProvider.Create("redb-c6-disabled"),
            fakeTime,
            new InMemoryFederationStateNonceStore(fakeTime),
            new FederationStateOptions { RequireOneTimeUse = false });

        var encrypted = protector.Protect(new FederationState { ProviderId = "google" });

        var (_, f1) = await protector.UnprotectAsync(encrypted, bindingSecret: null);
        var (_, f2) = await protector.UnprotectAsync(encrypted, bindingSecret: null);

        f1.Should().Be(FederationStateValidationFailure.None);
        f2.Should().Be(FederationStateValidationFailure.None);
    }
}
