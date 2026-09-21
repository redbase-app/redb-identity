using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Contracts.Routes;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Security;

/// <summary>
/// An administrative scope reaches a user only through a role that carries it.
/// <para>
/// OAuth's scope check asks whether the <b>client</b> may request a scope, never whether the person
/// should hold it. The admin console legitimately asks for <c>identity:manage</c>, so before the
/// entitlement gate every account able to sign in to it received the master management scope — and
/// the management API, checking the token exactly as it should, let them administer. Reproduced on a
/// running instance before the fix: a freshly registered account with no roles read the user list and
/// deleted a user.
/// </para>
/// <para>
/// These tests pin both directions through the real token pipeline: no entitling role means the scope
/// is not in the issued token, an entitling role means it is, and <c>client_credentials</c> — which
/// has no user to entitle — is left exactly as the client's own permissions decide.
/// </para>
/// </summary>
[Collection("ProductionBootstrap")]
public sealed class AdminScopeEntitlementTests : IAsyncLifetime
{
    private const string AdminClientId = "entitlement-test-console";
    private const string AdminClientSecret = "entitlement-test-secret-value";
    private const string ManagementScope = "identity:manage";

    /// <summary>Own role, not the seeded "admin" one: this test must not depend on, or disturb, seeded data.</summary>
    private const string RoleName = "entitlement-test-admin";

    private readonly ProductionBootstrapFixture _fx;

    private string _plainUser = null!;
    private string _rolefulUser = null!;
    private const string Password = "Test@Password123";

    public AdminScopeEntitlementTests(ProductionBootstrapFixture fx) => _fx = fx;

    public async Task InitializeAsync()
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        _plainUser = $"entitle-plain-{suffix}";
        _rolefulUser = $"entitle-admin-{suffix}";

        // A console-shaped client: permitted to ASK for the management scope, exactly like the real
        // one. That permission is the whole point — it is what used to be sufficient on its own.
        var manager = _fx.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        if (await manager.FindByClientIdAsync(AdminClientId) is null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = AdminClientId,
                ClientSecret = AdminClientSecret,
                DisplayName = "Entitlement test console",
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    // Introspection is how these tests read what a token actually carries; the
                    // token response cannot answer it (RFC 6749 §5.1 makes `scope` optional there).
                    OpenIddictConstants.Permissions.Endpoints.Introspection,
                    OpenIddictConstants.Permissions.GrantTypes.Password,
                    OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                    OpenIddictConstants.Permissions.Prefixes.Scope + "openid",
                    OpenIddictConstants.Permissions.Prefixes.Scope + ManagementScope,
                },
            });
        }

        await _fx.WithRedb(async redb =>
        {
            await CreateUserAsync(redb, _plainUser);
            var rolefulId = await CreateUserAsync(redb, _rolefulUser);

            // Give the second user a role that carries the management scope — the supported way to
            // hold it. The role and the scope object are created here rather than taken from the
            // startup seeders: this fixture builds its own pipeline and does not run them, and a test
            // that quietly depends on seeded data fails for the wrong reason when the seeding moves.
            var svc = new RoleService(redb);
            var role = await redb.Query<RoleProps>()
                .Where(p => p.Name == RoleName)
                .Where(p => p.Audience == "organization")
                .FirstOrDefaultAsync()
                ?? await svc.CreateRoleAsync(RoleName, "organization", applicationId: null,
                    displayName: "Entitlement test admin",
                    description: "Carries the management scope for the entitlement tests.");

            var scope = await redb.Query<ScopeProps>()
                .Where(p => p.ScopeName == ManagementScope)
                .FirstOrDefaultAsync();
            if (scope is null)
            {
                scope = new RedbObject<ScopeProps>(new ScopeProps { ScopeName = ManagementScope })
                {
                    Name = ManagementScope,
                };
                await redb.SaveAsync(scope);
            }

            await svc.AttachScopeAsync(role.Id, scope.Id, actingUserId: null);
            await svc.AssignUserAsync(role.Id, rolefulId, actingUserId: null);
        });
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private static async Task<long> CreateUserAsync(IRedbService redb, string login)
    {
        var existing = await redb.UserProvider.GetUserByLoginAsync(login);
        if (existing is not null) return existing.Id;

        var created = await redb.UserProvider.CreateUserAsync(new redb.Core.Models.Users.CreateUserRequest
        {
            Login = login,
            Password = Password,
            Name = login,
            Email = $"{login}@entitlement.test",
        });
        return created.Id;
    }

    private async Task<string[]> IssuedScopesAsync(string username)
    {
        var result = await _fx.Request(IdentityEndpoints.Token, new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = username,
            ["password"] = Password,
            ["client_id"] = AdminClientId,
            ["client_secret"] = AdminClientSecret,
            ["scope"] = $"openid {ManagementScope}",
        });

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().NotContainKey("error",
            "the request must succeed - an unentitled scope is dropped, it does not fail the sign-in");
        return await IntrospectedScopesAsync(response["access_token"]!.ToString()!);
    }

    /// <summary>
    /// What the issued token actually carries, asked of the server itself.
    /// <para>
    /// Not read from the token response: RFC 6749 §5.1 makes its <c>scope</c> member optional when the
    /// issued scope equals the requested one, so its absence is ambiguous — "unchanged" and "nothing
    /// granted" look the same. Introspection (RFC 7662) answers about the token in hand.
    /// </para>
    /// </summary>
    private async Task<string[]> IntrospectedScopesAsync(string accessToken)
    {
        var result = await _fx.Request(IdentityEndpoints.Introspect, new Dictionary<string, string>
        {
            ["token"] = accessToken,
            ["client_id"] = AdminClientId,
            ["client_secret"] = AdminClientSecret,
        });

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().NotContainKey("error");
        response["active"].Should().Be(true, "a freshly issued token is active");

        var raw = response.TryGetValue("scope", out var s) ? s?.ToString() : null;
        return string.IsNullOrWhiteSpace(raw)
            ? Array.Empty<string>()
            : raw!.Split(' ', StringSplitOptions.RemoveEmptyEntries);
    }

    [Fact]
    public async Task A_user_without_an_entitling_role_does_not_receive_the_management_scope()
    {
        var scopes = await IssuedScopesAsync(_plainUser);

        scopes.Should().NotContain(ManagementScope,
            "the client may ASK for it, but nothing about this user grants it - that gap is what let "
            + "every account that could sign in to the console administer the whole surface");
        scopes.Should().Contain("openid", "the rest of the request is untouched; only the unentitled scope is dropped");
    }

    [Fact]
    public async Task A_user_whose_role_carries_it_does_receive_the_management_scope()
    {
        var scopes = await IssuedScopesAsync(_rolefulUser);

        scopes.Should().Contain(ManagementScope,
            "the administrator holds it through the admin role - otherwise the gate would lock the console's owner out");
    }

    [Fact]
    public async Task Client_credentials_are_left_to_the_client_permissions()
    {
        // No user, nothing to entitle: the application's own scp:{scope} permission stays the
        // authoritative gate, exactly as OAuth intends for this grant.
        var result = await _fx.Request(IdentityEndpoints.Token, new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = AdminClientId,
            ["client_secret"] = AdminClientSecret,
            ["scope"] = ManagementScope,
        });

        var response = result.Should().BeOfType<Dictionary<string, object?>>().Subject;
        response.Should().NotContainKey("error");
        var scopes = await IntrospectedScopesAsync(response["access_token"]!.ToString()!);
        scopes.Should().Contain(ManagementScope);
    }
}
