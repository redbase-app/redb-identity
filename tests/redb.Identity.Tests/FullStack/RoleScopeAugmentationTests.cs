using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using AwesomeAssertions;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// Scopes attached to a role reach a token only when the client asked for them.
/// <para>
/// Before, <c>AttachRoleRegistryClaims</c> added every scope of the user's roles to every token of that
/// user, for any client, after the request had been checked against the client's permissions. A client
/// that could not even request <c>identity:manage</c> received an administrator's token carrying it, with
/// Identity's own audience, and the management API accepted that token: signing in to any application
/// handed it the administration of Identity. Now a role is an entitlement only: the client asks, OpenIddict
/// checks the client's permission, and the user's role decides whether a gated scope stays.
/// </para>
/// </summary>
[Collection("ProductionHttp")]
public sealed class RoleScopeAugmentationTests : IAsyncLifetime
{
    private const string ThirdPartyClientId = "rolescope-third-party";
    private const string ThirdPartySecret = "rolescope-third-party-secret-value";
    private const string ConsoleClientId = "rolescope-console";
    private const string ConsoleSecret = "rolescope-console-secret-value";
    private const string ManagementScope = "identity:manage";
    private const string RoleName = "rolescope-test-admin";
    private const string Password = "RoleScope@Test123!";

    private readonly ProductionHttpFixture _fx;
    private string _admin = null!;
    private string _plain = null!;

    public RoleScopeAugmentationTests(ProductionHttpFixture fx) => _fx = fx;

    public async Task InitializeAsync()
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        _admin = "rolescope-admin-" + suffix;
        _plain = "rolescope-plain-" + suffix;

        var manager = _fx.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        // A third-party client: it may sign users in and introspect its own tokens, nothing more. No
        // scp:identity:manage, so it may not even request the management scope.
        await EnsureClientAsync(manager, ThirdPartyClientId, ThirdPartySecret, withManagementScope: false);
        // A console-shaped client: permitted to ask for the management scope, like Identity Web.
        await EnsureClientAsync(manager, ConsoleClientId, ConsoleSecret, withManagementScope: true);

        // An administrator through a role that carries the management scope, as the seeded admin role
        // does, and a user without any role.
        await _fx.UseRedbAsync(async redb =>
        {
            var admin = await CreateUserAsync(redb, _admin);
            await CreateUserAsync(redb, _plain);

            var svc = new RoleService(redb);
            var role = await redb.Query<RoleProps>()
                .Where(p => p.Name == RoleName)
                .Where(p => p.Audience == "organization")
                .FirstOrDefaultAsync()
                ?? await svc.CreateRoleAsync(RoleName, "organization", applicationId: null,
                    displayName: "Role scope test admin", description: "Carries identity:manage.");

            var scope = await redb.Query<ScopeProps>()
                .Where(p => p.ScopeName == ManagementScope)
                .FirstOrDefaultAsync();
            if (scope is null)
            {
                scope = new RedbObject<ScopeProps>(new ScopeProps { ScopeName = ManagementScope }) { Name = ManagementScope };
                await redb.SaveAsync(scope);
            }

            if (!(await svc.ListScopeIdsForRoleAsync(role.Id)).Contains(scope.Id))
                await svc.AttachScopeAsync(role.Id, scope.Id, actingUserId: null);
            await svc.AssignUserAsync(role.Id, admin, actingUserId: null);
            return 0;
        });
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task A_client_without_the_permission_gets_no_role_scope_and_its_token_does_not_administer()
    {
        var token = await TokenAsync(ThirdPartyClientId, ThirdPartySecret, _admin, "openid");

        (await ScopesAsync(token, ThirdPartyClientId, ThirdPartySecret)).Should().NotContain(ManagementScope,
            "the role's scope is not added: the client neither asked for it nor may request it");

        using var response = await ManagementCallAsync(token);
        response.StatusCode.Should().BeOneOf([HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden],
            "the token of a third-party client must not administer Identity");
    }

    [Fact]
    public async Task A_client_without_the_permission_cannot_request_the_scope_either()
    {
        using var response = await _fx.Http.PostAsync("/connect/token", Form(ThirdPartyClientId, ThirdPartySecret, _admin, $"openid {ManagementScope}"));
        var body = JsonSerializer.Deserialize<JsonElement>(await response.Content.ReadAsStringAsync());

        response.IsSuccessStatusCode.Should().BeFalse("the client's permissions are checked on the request");
        // OpenIddict refuses a scope the client may not use as invalid_request (ID2051).
        body.GetProperty("error").GetString().Should().BeOneOf("invalid_request", "invalid_scope");
    }

    [Fact]
    public async Task Without_a_request_the_role_scope_is_absent_even_for_a_permitted_client()
    {
        var token = await TokenAsync(ConsoleClientId, ConsoleSecret, _admin, "openid");

        (await ScopesAsync(token, ConsoleClientId, ConsoleSecret)).Should().NotContain(ManagementScope,
            "a role entitles a requested scope, it does not add one");
    }

    [Fact]
    public async Task Requested_and_carried_by_a_role_the_scope_is_issued_and_administers()
    {
        var token = await TokenAsync(ConsoleClientId, ConsoleSecret, _admin, $"openid {ManagementScope}");

        (await ScopesAsync(token, ConsoleClientId, ConsoleSecret)).Should().Contain(ManagementScope);

        using var response = await ManagementCallAsync(token);
        response.StatusCode.Should().Be(HttpStatusCode.OK, "the administrator asked through the console: {0}",
            await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Requested_without_a_role_the_scope_is_dropped()
    {
        var token = await TokenAsync(ConsoleClientId, ConsoleSecret, _plain, $"openid {ManagementScope}");

        (await ScopesAsync(token, ConsoleClientId, ConsoleSecret)).Should().NotContain(ManagementScope,
            "nothing about this user entitles the management scope");
    }

    private static async Task EnsureClientAsync(IOpenIddictApplicationManager manager, string clientId, string secret, bool withManagementScope)
    {
        if (await manager.FindByClientIdAsync(clientId) is not null)
            return;
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientSecret = secret,
            DisplayName = "Role scope test: " + clientId,
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.Introspection,
                OpenIddictConstants.Permissions.GrantTypes.Password,
                OpenIddictConstants.Permissions.Prefixes.Scope + "openid",
            },
        };
        if (withManagementScope)
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Scope + ManagementScope);
        await manager.CreateAsync(descriptor);
    }

    private static async Task<long> CreateUserAsync(IRedbService redb, string login) =>
        (await redb.UserProvider.CreateUserAsync(new redb.Core.Models.Users.CreateUserRequest
        {
            Login = login,
            Password = Password,
            Name = login,
            Email = $"{login}@rolescope.test",
        })).Id;

    private static FormUrlEncodedContent Form(string clientId, string secret, string user, string scope) => new(new Dictionary<string, string>
    {
        ["grant_type"] = "password",
        ["username"] = user,
        ["password"] = Password,
        ["client_id"] = clientId,
        ["client_secret"] = secret,
        ["scope"] = scope,
    });

    private async Task<string> TokenAsync(string clientId, string secret, string user, string scope)
    {
        using var response = await _fx.Http.PostAsync("/connect/token", Form(clientId, secret, user, scope));
        var body = await response.Content.ReadAsStringAsync();
        response.StatusCode.Should().Be(HttpStatusCode.OK, "token: {0}", body);
        return JsonSerializer.Deserialize<JsonElement>(body).GetProperty("access_token").GetString()!;
    }

    // What the token carries, asked of Identity itself; the token answer may omit "scope" (RFC 6749 §5.1).
    private async Task<string[]> ScopesAsync(string token, string clientId, string secret)
    {
        using var response = await _fx.Http.PostAsync("/connect/introspect", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = token,
            ["client_id"] = clientId,
            ["client_secret"] = secret,
        }));
        var body = JsonSerializer.Deserialize<JsonElement>(await response.Content.ReadAsStringAsync());
        body.GetProperty("active").GetBoolean().Should().BeTrue();
        return body.TryGetProperty("scope", out var scope) ? scope.GetString()!.Split(' ', StringSplitOptions.RemoveEmptyEntries) : [];
    }

    private async Task<HttpResponseMessage> ManagementCallAsync(string token)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/identity/users");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await _fx.Http.SendAsync(request);
    }
}
