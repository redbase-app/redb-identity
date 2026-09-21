using FluentAssertions;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Security;

/// <summary>
/// The scope attachments of a role are the role's own, not everything hanging off it.
/// <para>
/// A role is the parent of two unrelated kinds of child object: the users assigned to it and the
/// scopes attached to it. Both carry a bigint in the same base column, so a query that selects
/// children of the role without pinning the kind reads user ids as scope ids. That is not academic:
/// on the running instance it made <see cref="RoleService.ListScopeIdsForRoleAsync"/> report
/// attachments for a role whose scope list is empty, which in turn made the startup seeder believe
/// the admin role was already curated and skip it, leaving every administrator without the scope
/// their role is supposed to carry.
/// </para>
/// </summary>
[Collection("ProductionBootstrap")]
public sealed class RoleScopeQueryIsolationTests
{
    private readonly ProductionBootstrapFixture _fx;

    public RoleScopeQueryIsolationTests(ProductionBootstrapFixture fx) => _fx = fx;

    [Fact]
    public async Task A_role_with_users_and_no_scopes_reports_no_attached_scopes()
    {
        await _fx.WithRedb(async redb =>
        {
            var svc = new RoleService(redb);
            var suffix = Guid.NewGuid().ToString("N")[..8];

            var role = await svc.CreateRoleAsync($"scope-isolation-{suffix}", "organization",
                applicationId: null, displayName: "Scope isolation", description: "No scopes attached, on purpose.");

            var user = await redb.UserProvider.CreateUserAsync(new redb.Core.Models.Users.CreateUserRequest
            {
                Login = $"scope-isolation-user-{suffix}",
                Password = "Test@Password123",
                Name = "Scope isolation user",
                Email = $"scope-isolation-{suffix}@entitlement.test",
            });
            await svc.AssignUserAsync(role.Id, user.Id, actingUserId: null);

            var attached = await svc.ListScopeIdsForRoleAsync(role.Id);
            attached.Should().BeEmpty(
                "nothing was attached - the user assignment is a different kind of child object, and "
                + "reading its user id as a scope id makes an empty role look curated");

            var names = await svc.GetEffectiveScopeNamesAsync(new[] { role.Id });
            names.Should().BeEmpty("a role with no scope attachments grants no scopes");
        });
    }

    [Fact]
    public async Task An_attached_scope_is_the_only_thing_reported()
    {
        await _fx.WithRedb(async redb =>
        {
            var svc = new RoleService(redb);
            var suffix = Guid.NewGuid().ToString("N")[..8];

            var role = await svc.CreateRoleAsync($"scope-isolation-both-{suffix}", "organization",
                applicationId: null, displayName: "Scope isolation", description: "One user, one scope.");

            var user = await redb.UserProvider.CreateUserAsync(new redb.Core.Models.Users.CreateUserRequest
            {
                Login = $"scope-isolation-both-{suffix}",
                Password = "Test@Password123",
                Name = "Scope isolation user",
                Email = $"scope-isolation-both-{suffix}@entitlement.test",
            });
            await svc.AssignUserAsync(role.Id, user.Id, actingUserId: null);

            var scopeName = $"isolation:{suffix}";
            var scope = new RedbObject<ScopeProps>(new ScopeProps { ScopeName = scopeName }) { Name = scopeName };
            await redb.SaveAsync(scope);
            await svc.AttachScopeAsync(role.Id, scope.Id, actingUserId: null);

            var attached = await svc.ListScopeIdsForRoleAsync(role.Id);
            attached.Should().Equal(scope.Id);

            var names = await svc.GetEffectiveScopeNamesAsync(new[] { role.Id });
            names.Should().BeEquivalentTo(new[] { scopeName });
        });
    }
}
