using FluentAssertions;
using redb.Identity.Ldap;
using Xunit;

namespace redb.Identity.Tests.Ldap;

/// <summary>
/// Unit tests for <see cref="LdapExternalUserProvider"/> logic that doesn't require a live LDAP server.
/// Tests LDAP filter escaping (RFC 4515) and constructor validation.
/// </summary>
public class LdapExternalUserProviderTests
{
    // ── LDAP Filter Escaping (RFC 4515 §3) ──

    [Theory]
    [InlineData("alice", "alice")]
    [InlineData("bob.smith", "bob.smith")]
    [InlineData("user@domain.com", "user@domain.com")]
    public void EscapeLdapFilter_PlainValues_Unchanged(string input, string expected)
    {
        LdapExternalUserProvider.EscapeLdapFilter(input).Should().Be(expected);
    }

    [Theory]
    [InlineData("user*", "user\\2a")]
    [InlineData("(admin)", "\\28admin\\29")]
    [InlineData("dn\\path", "dn\\5cpath")]
    [InlineData("null\0char", "null\\00char")]
    [InlineData("a]l*i(c)e", "a]l\\2ai\\28c\\29e")]
    public void EscapeLdapFilter_SpecialChars_AreEscaped(string input, string expected)
    {
        LdapExternalUserProvider.EscapeLdapFilter(input).Should().Be(expected);
    }

    [Fact]
    public void EscapeLdapFilter_InjectionAttempt_IsNeutralized()
    {
        // Classic LDAP injection: username = "admin)(|(uid=*"
        var malicious = "admin)(|(uid=*";
        var escaped = LdapExternalUserProvider.EscapeLdapFilter(malicious);

        escaped.Should().Be("admin\\29\\28|\\28uid=\\2a");
        escaped.Should().NotContain(")(");
        escaped.Should().NotContain("*");
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void EscapeLdapFilter_NullOrEmpty_ReturnsSame(string? input)
    {
        LdapExternalUserProvider.EscapeLdapFilter(input!).Should().Be(input);
    }

    // ── Constructor validation ──

    [Fact]
    public void Constructor_InvalidOptions_Throws()
    {
        var options = new LdapProviderOptions { UserBaseDn = "" }; // invalid

        var act = () => new LdapExternalUserProvider(
            options,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<LdapExternalUserProvider>.Instance);

        act.Should().Throw<InvalidOperationException>().WithMessage("*UserBaseDn*");
    }

    [Fact]
    public void ProviderName_ReturnsConfiguredName()
    {
        var options = new LdapProviderOptions
        {
            ProviderName = "ldap:corp",
            UserBaseDn = "dc=test",
            UserFilter = "(uid={0})"
        };

        var provider = new LdapExternalUserProvider(
            options,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<LdapExternalUserProvider>.Instance);

        provider.ProviderName.Should().Be("ldap:corp");
        provider.Priority.Should().Be(100);
    }

    // ── Null/empty inputs ──

    [Fact]
    public async Task AuthenticateAsync_NullUsername_ReturnsNull()
    {
        var provider = CreateProvider();

        var result = await provider.AuthenticateAsync(null!, "password");
        result.Should().BeNull();
    }

    [Fact]
    public async Task AuthenticateAsync_EmptyPassword_ReturnsNull()
    {
        var provider = CreateProvider();

        var result = await provider.AuthenticateAsync("alice", "");
        result.Should().BeNull();
    }

    [Fact]
    public async Task AuthenticateAsync_WhitespaceUsername_ReturnsNull()
    {
        var provider = CreateProvider();

        var result = await provider.AuthenticateAsync("   ", "password");
        result.Should().BeNull();
    }

    // ── Domain hint parsing ──

    [Theory]
    [InlineData("alice@corp.test", "alice", "corp.test")]
    [InlineData("bob@EXAMPLE.COM", "bob", "EXAMPLE.COM")]
    [InlineData("CORP\\alice", "alice", "CORP")]
    [InlineData("domain\\user", "user", "domain")]
    public void ParseDomainHint_WithHint_ExtractsCorrectly(string input, string expectedUser, string expectedDomain)
    {
        var (username, domain) = LdapExternalUserProvider.ParseDomainHint(input);
        username.Should().Be(expectedUser);
        domain.Should().Be(expectedDomain);
    }

    [Theory]
    [InlineData("alice")]
    [InlineData("bob.smith")]
    [InlineData("plain_user")]
    public void ParseDomainHint_WithoutHint_ReturnsNullDomain(string input)
    {
        var (username, domain) = LdapExternalUserProvider.ParseDomainHint(input);
        username.Should().Be(input);
        domain.Should().BeNull();
    }

    [Theory]
    [InlineData("@domain")]      // empty username part
    [InlineData("\\user")]       // empty domain part
    [InlineData("user@")]        // empty domain after @
    [InlineData("domain\\")]     // empty username after \
    public void ParseDomainHint_EdgeCases_TreatsAsPlainOrPartial(string input)
    {
        var (username, domain) = LdapExternalUserProvider.ParseDomainHint(input);
        // Edge cases: at least one part is always present
        username.Should().NotBeNull();
    }

    // ── UserAccountControlFlags ──

    [Fact]
    public void UacFlags_AccountDisable_HasCorrectValue()
    {
        ((int)UserAccountControlFlags.AccountDisable).Should().Be(0x0002);
    }

    [Fact]
    public void UacFlags_Lockout_HasCorrectValue()
    {
        ((int)UserAccountControlFlags.Lockout).Should().Be(0x0010);
    }

    [Fact]
    public void UacFlags_NormalAccount_HasCorrectValue()
    {
        ((int)UserAccountControlFlags.NormalAccount).Should().Be(0x0200);
    }

    [Fact]
    public void UacFlags_PasswordExpired_HasCorrectValue()
    {
        ((int)UserAccountControlFlags.PasswordExpired).Should().Be(0x800000);
    }

    [Fact]
    public void UacFlags_CombinedFlags_WorkCorrectly()
    {
        var combined = UserAccountControlFlags.NormalAccount | UserAccountControlFlags.AccountDisable;
        combined.HasFlag(UserAccountControlFlags.AccountDisable).Should().BeTrue();
        combined.HasFlag(UserAccountControlFlags.NormalAccount).Should().BeTrue();
        combined.HasFlag(UserAccountControlFlags.Lockout).Should().BeFalse();
    }

    [Fact]
    public void UacFlags_DisabledAndNormal_ParsesFromInt()
    {
        // AD typical disabled user: NormalAccount(0x0200) + AccountDisable(0x0002) = 0x0202
        var flags = (UserAccountControlFlags)0x0202;
        flags.HasFlag(UserAccountControlFlags.AccountDisable).Should().BeTrue();
        flags.HasFlag(UserAccountControlFlags.NormalAccount).Should().BeTrue();
    }

    [Fact]
    public void UacFlags_LockedOut_ParsesFromInt()
    {
        // NormalAccount(0x0200) + Lockout(0x0010) = 0x0210
        var flags = (UserAccountControlFlags)0x0210;
        flags.HasFlag(UserAccountControlFlags.Lockout).Should().BeTrue();
        flags.HasFlag(UserAccountControlFlags.AccountDisable).Should().BeFalse();
    }

    [Fact]
    public async Task AuthenticateAsync_DomainMismatch_ReturnsNull()
    {
        var options = new LdapProviderOptions
        {
            UserBaseDn = "ou=users,dc=test",
            UserFilter = "(uid={0})",
            Server = "nonexistent.host",
            Domains = ["corp.test"]
        };
        options.ApplyPreset(LdapPreset.OpenLDAP);

        var provider = new LdapExternalUserProvider(
            options,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<LdapExternalUserProvider>.Instance);

        // Domain doesn't match configured domains → should return null (skip)
        var result = await provider.AuthenticateAsync("alice@other.test", "password");
        result.Should().BeNull();
    }

    [Fact]
    public async Task AuthenticateAsync_NoDomainHint_NoDomainConfig_Passes()
    {
        // When Domains is empty, bare usernames are accepted
        var provider = CreateProvider();

        // This will attempt LDAP connection to nonexistent.host and throw,
        // NOT return null — proving domain routing didn't filter it out.
        var act = () => provider.AuthenticateAsync("alice", "password");
        await act.Should().ThrowAsync<Exception>();
    }

    private static LdapExternalUserProvider CreateProvider()
    {
        var options = new LdapProviderOptions
        {
            UserBaseDn = "ou=users,dc=test",
            UserFilter = "(uid={0})",
            Server = "nonexistent.host",
            ConnectTimeoutSeconds = 1 // pre-flight probe fails fast on NXDOMAIN
        };
        options.ApplyPreset(LdapPreset.OpenLDAP);

        return new LdapExternalUserProvider(
            options,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<LdapExternalUserProvider>.Instance);
    }
}
