using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using redb.Identity.Core.Services;
using redb.Identity.Ldap;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Ldap;

/// <summary>
/// Tests for LDAP provider resilience and provider chain ordering.
/// These test the provider contract: exceptions are thrown (LoginService catches them),
/// priority ordering, and domain-routed multi-provider scenarios.
/// </summary>
public class LdapProviderResilienceTests
{
    // ── F: LDAP unavailable ──

    [Fact]
    public async Task AuthenticateAsync_UnreachableServer_ThrowsException()
    {
        // Provider with nonexistent host — should throw when LDAP call fails
        var options = new LdapProviderOptions
        {
            UserBaseDn = "ou=users,dc=test",
            UserFilter = "(uid={0})",
            Server = "192.0.2.1", // RFC 5737 TEST-NET — guaranteed unreachable
            Port = 389,
            OperationTimeoutSeconds = 2,
            ConnectTimeoutSeconds = 1 // pre-flight probe must fail fast
        };
        options.ApplyPreset(LdapPreset.OpenLDAP);

        var provider = new LdapExternalUserProvider(
            options,
            NullLogger<LdapExternalUserProvider>.Instance);

        // The provider should throw (not return null) — LoginService catches + skips
        var act = () => provider.AuthenticateAsync("alice", "password");
        await act.Should().ThrowAsync<Exception>();
    }

    // ── G: Provider priority ordering ──

    [Fact]
    public void Providers_SortedByPriority_LowerFirst()
    {
        var providerA = new FakeExternalUserProvider { ProviderName = "A", Priority = 50 };
        var providerB = new FakeExternalUserProvider { ProviderName = "B", Priority = 10 };
        var providerC = new FakeExternalUserProvider { ProviderName = "C", Priority = 100 };

        // Simulate what LoginService constructor does
        var sorted = new IExternalUserProvider[] { providerA, providerB, providerC }
            .OrderBy(p => p.Priority)
            .ToArray();

        sorted[0].ProviderName.Should().Be("B");
        sorted[1].ProviderName.Should().Be("A");
        sorted[2].ProviderName.Should().Be("C");
    }

    [Fact]
    public async Task ProviderChain_FirstMatchWins_OtherNotCalled()
    {
        var callLog = new List<string>();

        var provider1 = new FakeExternalUserProvider { ProviderName = "first", Priority = 10 };
        provider1.UserHandlers["alice"] = pwd =>
        {
            callLog.Add("first");
            return pwd == "secret"
                ? ExternalAuthResult.Success("alice-ext", displayName: "Alice")
                : ExternalAuthResult.Failed("Bad password");
        };

        var provider2 = new FakeExternalUserProvider { ProviderName = "second", Priority = 20 };
        provider2.UserHandlers["alice"] = pwd =>
        {
            callLog.Add("second");
            return ExternalAuthResult.Success("alice-2nd");
        };

        // Simulate the LoginService provider chain manually
        ExternalAuthResult? result = null;
        foreach (var p in new IExternalUserProvider[] { provider1, provider2 }.OrderBy(p => p.Priority))
        {
            result = await p.AuthenticateAsync("alice", "secret");
            if (result is not null) break;
        }

        result.Should().NotBeNull();
        result!.Succeeded.Should().BeTrue();
        result.ExternalId.Should().Be("alice-ext");
        callLog.Should().Equal("first"); // second provider never called
    }

    [Fact]
    public async Task ProviderChain_FirstReturnsNull_SecondTried()
    {
        var callLog = new List<string>();

        var provider1 = new FakeExternalUserProvider { ProviderName = "skip", Priority = 10 };
        // No handler for "bob" → returns null → skip

        var provider2 = new FakeExternalUserProvider { ProviderName = "catch", Priority = 20 };
        provider2.UserHandlers["bob"] = pwd =>
        {
            callLog.Add("catch");
            return ExternalAuthResult.Success("bob-ext");
        };

        ExternalAuthResult? result = null;
        foreach (var p in new IExternalUserProvider[] { provider1, provider2 }.OrderBy(p => p.Priority))
        {
            result = await p.AuthenticateAsync("bob", "password");
            if (result is not null) break;
        }

        result.Should().NotBeNull();
        result!.ExternalId.Should().Be("bob-ext");
        callLog.Should().Equal("catch");
    }

    [Fact]
    public async Task ProviderChain_FailedResult_StopsChain()
    {
        var provider1 = new FakeExternalUserProvider { ProviderName = "reject", Priority = 10 };
        provider1.UserHandlers["alice"] = _ => ExternalAuthResult.Failed("Account locked");

        var provider2 = new FakeExternalUserProvider { ProviderName = "fallback", Priority = 20 };
        provider2.UserHandlers["alice"] = _ => ExternalAuthResult.Success("alice-fallback");

        // Simulate LoginService chain: Failed means stop (don't try next)
        ExternalAuthResult? result = null;
        foreach (var p in new IExternalUserProvider[] { provider1, provider2 }.OrderBy(p => p.Priority))
        {
            result = await p.AuthenticateAsync("alice", "password");
            if (result is null) continue;
            break; // Both Success and Failed stop the chain
        }

        result.Should().NotBeNull();
        result!.Succeeded.Should().BeFalse();
        result.ErrorMessage.Should().Be("Account locked");
    }

    // ── Domain routing with multiple providers ──

    [Fact]
    public async Task DomainRouting_MatchingDomain_AcceptsUser()
    {
        var options = new LdapProviderOptions
        {
            UserBaseDn = "ou=users,dc=corp",
            UserFilter = "(uid={0})",
            Server = "nonexistent.host",
            Domains = ["corp.test", "CORP"],
            ConnectTimeoutSeconds = 1
        };
        options.ApplyPreset(LdapPreset.OpenLDAP);

        var provider = new LdapExternalUserProvider(
            options, NullLogger<LdapExternalUserProvider>.Instance);

        // UPN format: alice@corp.test → accepted (will throw connecting, which proves it wasn't filtered out)
        var act1 = () => provider.AuthenticateAsync("alice@corp.test", "password");
        await act1.Should().ThrowAsync<Exception>("matching domain should be accepted and attempt LDAP");

        // NT format: CORP\alice → accepted
        var act2 = () => provider.AuthenticateAsync("CORP\\alice", "password");
        await act2.Should().ThrowAsync<Exception>("matching NT domain should be accepted");
    }

    [Fact]
    public async Task DomainRouting_NonMatchingDomain_ReturnsNull()
    {
        var options = new LdapProviderOptions
        {
            UserBaseDn = "ou=users,dc=corp",
            UserFilter = "(uid={0})",
            Server = "nonexistent.host",
            Domains = ["corp.test"],
            ConnectTimeoutSeconds = 1
        };
        options.ApplyPreset(LdapPreset.OpenLDAP);

        var provider = new LdapExternalUserProvider(
            options, NullLogger<LdapExternalUserProvider>.Instance);

        var result = await provider.AuthenticateAsync("alice@other.test", "password");
        result.Should().BeNull("non-matching domain should skip to next provider");

        var result2 = await provider.AuthenticateAsync("OTHER\\alice", "password");
        result2.Should().BeNull("non-matching NT domain should skip");
    }

    [Fact]
    public async Task DomainRouting_NoDomainHint_PassesThrough()
    {
        var options = new LdapProviderOptions
        {
            UserBaseDn = "ou=users,dc=corp",
            UserFilter = "(uid={0})",
            Server = "nonexistent.host",
            Domains = ["corp.test"],
            ConnectTimeoutSeconds = 1
        };
        options.ApplyPreset(LdapPreset.OpenLDAP);

        var provider = new LdapExternalUserProvider(
            options, NullLogger<LdapExternalUserProvider>.Instance);

        // Bare username with no domain hint → pass through (attempt LDAP)
        var act = () => provider.AuthenticateAsync("alice", "password");
        await act.Should().ThrowAsync<Exception>("bare username should still be tried");
    }

    [Fact]
    public void LdapProvider_Priority_IsConfigurable()
    {
        var options = new LdapProviderOptions
        {
            UserBaseDn = "dc=test",
            UserFilter = "(uid={0})",
            Priority = 42
        };

        var provider = new LdapExternalUserProvider(
            options, NullLogger<LdapExternalUserProvider>.Instance);

        provider.Priority.Should().Be(42);
    }
}
