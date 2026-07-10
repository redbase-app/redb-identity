using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using redb.Identity.Ldap;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.Ldap;

/// <summary>
/// Integration tests for <see cref="LdapExternalUserProvider"/> against a live OpenLDAP server.
/// Requires Docker container 'route-openldap' running on localhost:389.
/// Seed data: alice/alice123, bob/bob123, charlie/charlie123, diana/diana123, eve/eve123
/// Domain: dc=redb,dc=test. Users OU: ou=users,dc=redb,dc=test.
/// </summary>
[Trait("Category", "Integration")]
[Collection("LdapIntegration")]
public class LdapIntegrationTests : IAsyncLifetime
{
    private readonly ITestOutputHelper _out;
    private LdapExternalUserProvider _provider = null!;
    private bool _ldapAvailable;

    // ── OpenLDAP container settings ──
    private const string Server = "localhost";
    private const int Port = 389;
    private const string BindDn = "cn=admin,dc=redb,dc=test";
    private const string BindPassword = "admin";
    private const string UserBaseDn = "ou=users,dc=redb,dc=test";

    public LdapIntegrationTests(ITestOutputHelper output)
    {
        _out = output;
    }

    public async Task InitializeAsync()
    {
        var options = new LdapProviderOptions
        {
            Server = Server,
            Port = Port,
            BindDn = BindDn,
            BindPassword = BindPassword,
            UserBaseDn = UserBaseDn,
            ProviderName = "ldap:test"
        };
        options.ApplyPreset(LdapPreset.OpenLDAP);

        _provider = new LdapExternalUserProvider(
            options,
            NullLogger<LdapExternalUserProvider>.Instance);

        // Probe LDAP connectivity
        try
        {
            var probe = await _provider.AuthenticateAsync("alice", "alice123");
            _ldapAvailable = probe is { Succeeded: true };
            _out.WriteLine($"LDAP probe: available={_ldapAvailable}");
        }
        catch (Exception ex)
        {
            _out.WriteLine($"LDAP not available: {ex.Message}");
            _ldapAvailable = false;
        }
    }

    public Task DisposeAsync() => _provider.DisposeAsync().AsTask();

    private void SkipIfNoLdap()
    {
        if (!_ldapAvailable)
        {
            _out.WriteLine("SKIP: OpenLDAP container not available on localhost:389");
            Assert.Fail("OpenLDAP container not available on localhost:389. Start 'route-openldap' Docker container.");
        }
    }

    // ──────────────────────────────────────────────────────────
    //  Successful authentication
    // ──────────────────────────────────────────────────────────

    [Fact]
    public async Task Auth_ValidCredentials_ReturnsSuccess()
    {
        SkipIfNoLdap();

        var result = await _provider.AuthenticateAsync("alice", "alice123");

        result.Should().NotBeNull();
        result!.Succeeded.Should().BeTrue();
        result.ExternalId.Should().Be("alice");
        result.DisplayName.Should().Be("alice"); // cn=alice in seed data
        result.Email.Should().Be("alice@redb.test");
        result.Phone.Should().Be("+1-555-0101");
        result.FamilyName.Should().Be("Wonderland"); // sn
    }

    [Fact]
    public async Task Auth_AnotherUser_ReturnsCorrectProfile()
    {
        SkipIfNoLdap();

        var result = await _provider.AuthenticateAsync("bob", "bob123");

        result.Should().NotBeNull();
        result!.Succeeded.Should().BeTrue();
        result.ExternalId.Should().Be("bob");
        result.Email.Should().Be("bob@redb.test");
        result.FamilyName.Should().Be("Builder");
        result.Phone.Should().Be("+7-495-001-0002");
    }

    // ──────────────────────────────────────────────────────────
    //  Authentication failures
    // ──────────────────────────────────────────────────────────

    [Fact]
    public async Task Auth_WrongPassword_ReturnsFailed()
    {
        SkipIfNoLdap();

        var result = await _provider.AuthenticateAsync("alice", "wrongpassword");

        result.Should().NotBeNull();
        result!.Succeeded.Should().BeFalse();
        result.ErrorMessage.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task Auth_UnknownUser_ReturnsNull()
    {
        SkipIfNoLdap();

        var result = await _provider.AuthenticateAsync("nonexistent_user_xyz", "password");

        // null = provider doesn't handle this user
        result.Should().BeNull();
    }

    // ──────────────────────────────────────────────────────────
    //  Edge cases
    // ──────────────────────────────────────────────────────────

    [Fact]
    public async Task Auth_UserWithoutPhone_PhoneIsNull()
    {
        SkipIfNoLdap();

        // charlie has no telephoneNumber in seed data
        var result = await _provider.AuthenticateAsync("charlie", "charlie123");

        result.Should().NotBeNull();
        result!.Succeeded.Should().BeTrue();
        result.ExternalId.Should().Be("charlie");
        result.Email.Should().Be("charlie@redb.test");
        result.Phone.Should().BeNull();
    }

    [Fact]
    public async Task Auth_AllSeedUsers_Authenticate()
    {
        SkipIfNoLdap();

        var users = new[] { ("alice", "alice123"), ("bob", "bob123"), ("charlie", "charlie123"), ("diana", "diana123"), ("eve", "eve123") };

        foreach (var (username, password) in users)
        {
            var result = await _provider.AuthenticateAsync(username, password);
            result.Should().NotBeNull($"user '{username}' should be found");
            result!.Succeeded.Should().BeTrue($"user '{username}' should authenticate with correct password");
            result.ExternalId.Should().Be(username);

            _out.WriteLine($"  {username}: OK (email={result.Email}, sn={result.FamilyName})");
        }
    }

    // ──────────────────────────────────────────────────────────
    //  LDAP injection protection
    // ──────────────────────────────────────────────────────────

    [Fact]
    public async Task Auth_InjectionAttempt_DoesNotMatchAnyUser()
    {
        SkipIfNoLdap();

        // Classic LDAP injection: try to match all users
        var result = await _provider.AuthenticateAsync("*)(uid=*", "anything");

        result.Should().BeNull("injection attempt should not match any user");
    }

    // ──────────────────────────────────────────────────────────
    //  Attribute mapping with additional claims
    // ──────────────────────────────────────────────────────────

    [Fact]
    public async Task Auth_CustomAdditionalClaimsMap_MapsExtraAttributes()
    {
        SkipIfNoLdap();

        var options = new LdapProviderOptions
        {
            Server = Server,
            Port = Port,
            BindDn = BindDn,
            BindPassword = BindPassword,
            UserBaseDn = UserBaseDn,
            AdditionalClaimsMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["surname"] = "sn",
                ["ldap_mail"] = "mail"
            }
        };
        options.ApplyPreset(LdapPreset.OpenLDAP);

        await using var provider = new LdapExternalUserProvider(
            options,
            NullLogger<LdapExternalUserProvider>.Instance);

        var result = await provider.AuthenticateAsync("alice", "alice123");

        result.Should().NotBeNull();
        result!.Succeeded.Should().BeTrue();
        result.AdditionalClaims.Should().ContainKey("surname").WhoseValue.Should().Be("Wonderland");
        result.AdditionalClaims.Should().ContainKey("ldap_mail").WhoseValue.Should().Be("alice@redb.test");
    }
}
