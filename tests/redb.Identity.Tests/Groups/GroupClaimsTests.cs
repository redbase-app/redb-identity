using System.Security.Claims;
using FluentAssertions;
using OpenIddict.Abstractions;
using redb.Core;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using Xunit.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace redb.Identity.Tests.Groups;

/// <summary>
/// Tests for <see cref="GroupClaimsResolver"/> — enriching ClaimsPrincipal
/// with group/role claims based on scopes.
/// </summary>
[Collection("Postgres")]
public class GroupClaimsTests
{
    private readonly PostgresFixture _fx;
    private readonly ITestOutputHelper _output;

    public GroupClaimsTests(PostgresFixture fx, ITestOutputHelper output)
    {
        _fx = fx;
        _output = output;
    }

    private IGroupService CreateGroupService() => new GroupService(_fx.Redb);
    private GroupClaimsResolver CreateResolver() => new GroupClaimsResolver(_fx.Redb);

    private static ClaimsPrincipal BuildTestPrincipal(long userId, params string[] scopes)
    {
        var identity = new ClaimsIdentity("test");
        identity.AddClaim(new Claim(Claims.Subject, userId.ToString()));
        identity.AddClaim(new Claim(Claims.Name, $"user_{userId}"));
        identity.SetScopes(scopes);
        return new ClaimsPrincipal(identity);
    }

    [Fact]
    public async Task EnrichPrincipal_WithGroupsScope_AddsGroupClaims()
    {
        var svc = CreateGroupService();
        var resolver = CreateResolver();
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        var group1 = await svc.CreateGroupAsync("ClaimGroup1", "team");
        var group2 = await svc.CreateGroupAsync("ClaimGroup2", "department");
        await svc.AddMemberAsync(group1.id, userId, "member");
        await svc.AddMemberAsync(group2.id, userId, "admin");

        var principal = BuildTestPrincipal(userId, "openid", "groups");
        await resolver.EnrichPrincipalAsync(principal, userId, new[] { "openid", "groups" });

        var groupClaims = principal.FindAll(GroupClaimsResolver.GroupsClaim).Select(c => c.Value).ToList();
        groupClaims.Should().Contain("ClaimGroup1");
        groupClaims.Should().Contain("ClaimGroup2");

        _output.WriteLine($"Group claims: {string.Join(", ", groupClaims)}");
    }

    [Fact]
    public async Task EnrichPrincipal_WithRolesScope_AddsRoleClaims()
    {
        var svc = CreateGroupService();
        var resolver = CreateResolver();
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        var group1 = await svc.CreateGroupAsync("RoleClaimG1", "team");
        var group2 = await svc.CreateGroupAsync("RoleClaimG2", "department");
        await svc.AddMemberAsync(group1.id, userId, "editor");
        await svc.AddMemberAsync(group2.id, userId, "viewer");

        var principal = BuildTestPrincipal(userId, "openid", "roles");
        await resolver.EnrichPrincipalAsync(principal, userId, new[] { "openid", "roles" });

        var roleClaims = principal.FindAll(GroupClaimsResolver.RolesClaim).Select(c => c.Value).ToList();
        roleClaims.Should().Contain("editor");
        roleClaims.Should().Contain("viewer");

        _output.WriteLine($"Role claims: {string.Join(", ", roleClaims)}");
    }

    [Fact]
    public async Task EnrichPrincipal_WithBothScopes_AddsBothClaims()
    {
        var svc = CreateGroupService();
        var resolver = CreateResolver();
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        var group = await svc.CreateGroupAsync("BothScopeGroup", "team");
        await svc.AddMemberAsync(group.id, userId, "admin");

        var principal = BuildTestPrincipal(userId, "openid", "groups", "roles");
        await resolver.EnrichPrincipalAsync(principal, userId, new[] { "openid", "groups", "roles" });

        principal.FindAll(GroupClaimsResolver.GroupsClaim).Should().NotBeEmpty();
        principal.FindAll(GroupClaimsResolver.RolesClaim).Should().NotBeEmpty();
    }

    [Fact]
    public async Task EnrichPrincipal_WithoutGroupsOrRolesScope_NoClaimsAdded()
    {
        var svc = CreateGroupService();
        var resolver = CreateResolver();
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        var group = await svc.CreateGroupAsync("NoScopeGroup", "team");
        await svc.AddMemberAsync(group.id, userId, "member");

        var principal = BuildTestPrincipal(userId, "openid", "profile");
        await resolver.EnrichPrincipalAsync(principal, userId, new[] { "openid", "profile" });

        principal.FindAll(GroupClaimsResolver.GroupsClaim).Should().BeEmpty();
        principal.FindAll(GroupClaimsResolver.RolesClaim).Should().BeEmpty();
    }

    [Fact]
    public async Task EnrichPrincipal_DuplicateRoles_Deduplicated()
    {
        var svc = CreateGroupService();
        var resolver = CreateResolver();
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        var group1 = await svc.CreateGroupAsync("DedupG1", "team");
        var group2 = await svc.CreateGroupAsync("DedupG2", "team");
        await svc.AddMemberAsync(group1.id, userId, "member");
        await svc.AddMemberAsync(group2.id, userId, "member"); // same role

        var principal = BuildTestPrincipal(userId, "openid", "roles");
        await resolver.EnrichPrincipalAsync(principal, userId, new[] { "openid", "roles" });

        var roleClaims = principal.FindAll(GroupClaimsResolver.RolesClaim).Select(c => c.Value).ToList();
        // "member" should appear only once
        roleClaims.Count(r => r == "member").Should().Be(1, "duplicate roles should be deduplicated");
    }

    [Fact]
    public async Task EnrichPrincipal_ExpiredMembership_NotIncluded()
    {
        var svc = CreateGroupService();
        var resolver = CreateResolver();
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        var active = await svc.CreateGroupAsync("ClaimActiveG", "team");
        var expired = await svc.CreateGroupAsync("ClaimExpiredG", "team");
        await svc.AddMemberAsync(active.id, userId, "member");
        await svc.AddMemberAsync(expired.id, userId, "member",
            expiresAt: DateTimeOffset.UtcNow.AddHours(-1));

        var principal = BuildTestPrincipal(userId, "openid", "groups");
        await resolver.EnrichPrincipalAsync(principal, userId, new[] { "openid", "groups" });

        var groupClaims = principal.FindAll(GroupClaimsResolver.GroupsClaim).Select(c => c.Value).ToList();
        groupClaims.Should().Contain("ClaimActiveG");
        groupClaims.Should().NotContain("ClaimExpiredG");
    }

    [Fact]
    public async Task EnrichPrincipal_WithGroupsScope_AddsOrgClaim()
    {
        var svc = CreateGroupService();
        var resolver = CreateResolver();
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        var org = await svc.CreateGroupAsync("OrgClaimCorp", "organization");
        var team = await svc.CreateGroupAsync("OrgClaimTeam", "team");
        await svc.AddMemberAsync(org.id, userId, "member");
        await svc.AddMemberAsync(team.id, userId, "admin");

        var principal = BuildTestPrincipal(userId, "openid", "groups");
        await resolver.EnrichPrincipalAsync(principal, userId, new[] { "openid", "groups" });

        var orgClaims = principal.FindAll(GroupClaimsResolver.OrgClaim).Select(c => c.Value).ToList();
        orgClaims.Should().ContainSingle().Which.Should().Be("OrgClaimCorp");

        _output.WriteLine($"Org claim: {string.Join(", ", orgClaims)}");
    }

    [Fact]
    public async Task EnrichPrincipal_WithoutOrgTypeGroup_NoOrgClaim()
    {
        var svc = CreateGroupService();
        var resolver = CreateResolver();
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        var team = await svc.CreateGroupAsync("NoOrgTeam", "team");
        await svc.AddMemberAsync(team.id, userId, "member");

        var principal = BuildTestPrincipal(userId, "openid", "groups");
        await resolver.EnrichPrincipalAsync(principal, userId, new[] { "openid", "groups" });

        principal.FindAll(GroupClaimsResolver.OrgClaim).Should().BeEmpty(
            "no organization-type group means no org claim");
    }

    // ── Composite group inheritance via tree-hierarchy (DoD §5 H2 closure) ──

    [Fact]
    public async Task EnrichPrincipal_GroupsScope_IncludesAncestorGroupNames()
    {
        // Tree: company → engineering → developers
        // User is direct member of "developers" — should also receive
        // "engineering" and "company" via tree-ancestor traversal.
        var svc = CreateGroupService();
        var resolver = CreateResolver();
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var suffix = userId.ToString();

        var company = await svc.CreateGroupAsync($"InheritCompany_{suffix}", "organization");
        var engineering = await svc.CreateChildGroupAsync(company.id, $"InheritEngineering_{suffix}", "department");
        var developers = await svc.CreateChildGroupAsync(engineering.id, $"InheritDevelopers_{suffix}", "team");
        await svc.AddMemberAsync(developers.id, userId, "member");

        var principal = BuildTestPrincipal(userId, "openid", "groups");
        await resolver.EnrichPrincipalAsync(principal, userId, new[] { "openid", "groups" });

        var groupClaims = principal.FindAll(GroupClaimsResolver.GroupsClaim).Select(c => c.Value).ToList();
        groupClaims.Should().Contain($"InheritDevelopers_{suffix}", "direct membership");
        groupClaims.Should().Contain($"InheritEngineering_{suffix}", "ancestor (parent)");
        groupClaims.Should().Contain($"InheritCompany_{suffix}", "ancestor (grandparent / root)");

        _output.WriteLine($"Inherited group claims: {string.Join(", ", groupClaims)}");
    }

    [Fact]
    public async Task EnrichPrincipal_GroupsScope_DeduplicatesAncestorsWhenSharedAcrossMemberships()
    {
        // Tree: rootShared → branchA, branchB
        // User is member of both branchA and branchB — should receive
        // "rootShared" exactly once (no duplicate ancestor claim).
        var svc = CreateGroupService();
        var resolver = CreateResolver();
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var suffix = userId.ToString();

        var root = await svc.CreateGroupAsync($"SharedRoot_{suffix}", "organization");
        var branchA = await svc.CreateChildGroupAsync(root.id, $"BranchA_{suffix}", "team");
        var branchB = await svc.CreateChildGroupAsync(root.id, $"BranchB_{suffix}", "team");
        await svc.AddMemberAsync(branchA.id, userId, "member");
        await svc.AddMemberAsync(branchB.id, userId, "member");

        var principal = BuildTestPrincipal(userId, "openid", "groups");
        await resolver.EnrichPrincipalAsync(principal, userId, new[] { "openid", "groups" });

        var groupClaims = principal.FindAll(GroupClaimsResolver.GroupsClaim).Select(c => c.Value).ToList();
        groupClaims.Count(c => c == $"SharedRoot_{suffix}").Should().Be(1, "ancestor shared by two direct memberships should appear once");
    }

    [Fact]
    public async Task EnrichPrincipal_GroupsScope_OrgClaimFallsBackToAncestor()
    {
        // Tree: orgRoot (organization) → team (no org-type)
        // User is direct member only of "team" — org claim should fall back
        // to ancestor organization-type group "orgRoot".
        var svc = CreateGroupService();
        var resolver = CreateResolver();
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var suffix = userId.ToString();

        var orgRoot = await svc.CreateGroupAsync($"OrgRootInherited_{suffix}", "organization");
        var team = await svc.CreateChildGroupAsync(orgRoot.id, $"TeamInherited_{suffix}", "team");
        await svc.AddMemberAsync(team.id, userId, "member");

        var principal = BuildTestPrincipal(userId, "openid", "groups");
        await resolver.EnrichPrincipalAsync(principal, userId, new[] { "openid", "groups" });

        var orgClaims = principal.FindAll(GroupClaimsResolver.OrgClaim).Select(c => c.Value).ToList();
        orgClaims.Should().ContainSingle().Which.Should().Be($"OrgRootInherited_{suffix}",
            "org claim should fall back to closest organization-type ancestor when no direct organization membership exists");
    }

    [Fact]
    public async Task EnrichPrincipal_RolesScope_PerMembershipRolesAreNotInherited()
    {
        // Tree: parent (with no user membership) → child (user is member with role="editor")
        // The "editor" role applies only to the child membership; the parent group
        // does NOT auto-grant a role to the user (per-membership Role label is not transitive).
        var svc = CreateGroupService();
        var resolver = CreateResolver();
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var suffix = userId.ToString();

        var parent = await svc.CreateGroupAsync($"NoInheritParent_{suffix}", "team");
        var child = await svc.CreateChildGroupAsync(parent.id, $"NoInheritChild_{suffix}", "team");
        await svc.AddMemberAsync(child.id, userId, "editor");

        var principal = BuildTestPrincipal(userId, "openid", "roles");
        await resolver.EnrichPrincipalAsync(principal, userId, new[] { "openid", "roles" });

        var roleClaims = principal.FindAll(GroupClaimsResolver.RolesClaim).Select(c => c.Value).ToList();
        roleClaims.Should().Contain("editor", "direct membership emits its role");
        // No additional inherited role beyond "editor" — per-membership label, not transitive.
        roleClaims.Count(r => r == "editor").Should().Be(1);
    }
}
