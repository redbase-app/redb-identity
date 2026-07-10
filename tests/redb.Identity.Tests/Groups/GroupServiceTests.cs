using FluentAssertions;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.Groups;

/// <summary>
/// Store-level tests for <see cref="GroupService"/>.
/// Uses <see cref="PostgresFixture"/> (raw redb + PostgreSQL, no OpenIddict pipeline).
/// </summary>
[Collection("Postgres")]
public class GroupServiceTests
{
    private readonly PostgresFixture _fx;
    private readonly ITestOutputHelper _output;

    public GroupServiceTests(PostgresFixture fx, ITestOutputHelper output)
    {
        _fx = fx;
        _output = output;
    }

    private IGroupService CreateService() => new GroupService(_fx.Redb);

    // ── Group CRUD ──────────────────────────────────────────────

    [Fact]
    public async Task CreateGroup_ReturnsNewGroup()
    {
        var svc = CreateService();
        var group = await svc.CreateGroupAsync("Engineering", "department", "The engineering org");

        group.Should().NotBeNull();
        group.id.Should().BeGreaterThan(0);
        group.name.Should().Be("Engineering");
        group.Props.GroupType.Should().Be("department");
        group.Props.Description.Should().Be("The engineering org");

        _output.WriteLine($"Created group {group.id}: {group.name}");
    }

    [Fact]
    public async Task GetGroup_ReturnsExistingGroup()
    {
        var svc = CreateService();
        var created = await svc.CreateGroupAsync("GetTest", "team");

        var loaded = await svc.GetGroupAsync(created.id);

        loaded.Should().NotBeNull();
        loaded!.id.Should().Be(created.id);
        loaded.name.Should().Be("GetTest");
        loaded.Props.GroupType.Should().Be("team");
    }

    [Fact]
    public async Task GetGroup_NonExistent_ReturnsNull()
    {
        var svc = CreateService();
        var result = await svc.GetGroupAsync(999999999);
        result.Should().BeNull();
    }

    [Fact]
    public async Task UpdateGroup_ModifiesFields()
    {
        var svc = CreateService();
        var group = await svc.CreateGroupAsync("BeforeUpdate", "team");

        await svc.UpdateGroupAsync(group.id, name: "AfterUpdate", description: "Updated desc");

        var loaded = await svc.GetGroupAsync(group.id);
        loaded!.name.Should().Be("AfterUpdate");
        loaded.Props.Description.Should().Be("Updated desc");
        loaded.Props.GroupType.Should().Be("team"); // unchanged
    }

    [Fact]
    public async Task DeleteGroup_RemovesGroup()
    {
        var svc = CreateService();
        var group = await svc.CreateGroupAsync("ToDelete", "team");

        await svc.DeleteGroupAsync(group.id);

        var loaded = await svc.GetGroupAsync(group.id);
        loaded.Should().BeNull();
    }

    [Fact]
    public async Task DeleteGroup_AlsoRemovesMembers()
    {
        var svc = CreateService();
        var group = await svc.CreateGroupAsync("DeleteWithMembers", "team");
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        await svc.AddMemberAsync(group.id, userId);

        await svc.DeleteGroupAsync(group.id);

        // Member should also be gone — user-groups should not reference deleted group
        var userGroups = await svc.GetUserGroupsAsync(userId);
        userGroups.Should().NotContain(g => g.GroupId == group.id);
    }

    // ── Tree operations ─────────────────────────────────────────

    [Fact]
    public async Task CreateChildGroup_SetsParent()
    {
        var svc = CreateService();
        var parent = await svc.CreateGroupAsync("ParentOrg", "organization");
        var child = await svc.CreateChildGroupAsync(parent.id, "ChildTeam", "team");

        child.Should().NotBeNull();
        child.id.Should().BeGreaterThan(0);
        child.parent_id.Should().Be(parent.id);
        child.name.Should().Be("ChildTeam");

        _output.WriteLine($"Created child {child.id} under parent {parent.id}");
    }

    [Fact]
    public async Task GetChildGroups_ReturnsDirectChildren()
    {
        var svc = CreateService();
        var parent = await svc.CreateGroupAsync("ChildrenTestParent", "organization");
        await svc.CreateChildGroupAsync(parent.id, "Child1", "team");
        await svc.CreateChildGroupAsync(parent.id, "Child2", "team");

        var children = await svc.GetChildGroupsAsync(parent.id);

        children.Should().HaveCountGreaterOrEqualTo(2);
        children.Should().Contain(c => c.name == "Child1");
        children.Should().Contain(c => c.name == "Child2");
    }

    [Fact]
    public async Task ListRootGroups_ReturnsGroupsWithoutParent()
    {
        var svc = CreateService();
        var ts = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var rootName = $"Root_{ts}";
        await svc.CreateGroupAsync(rootName, "organization");

        var roots = await svc.ListRootGroupsAsync();

        roots.Should().Contain(g => g.name == rootName);
        roots.Should().OnlyContain(g => g.parent_id == null);
    }

    [Fact]
    public async Task LoadTree_ReturnsHierarchy()
    {
        var svc = CreateService();
        var root = await svc.CreateGroupAsync("TreeRoot", "organization");
        var dept = await svc.CreateChildGroupAsync(root.id, "TreeDept", "department");
        await svc.CreateChildGroupAsync(dept.id, "TreeTeam", "team");

        var tree = await svc.LoadTreeAsync(root.id);

        tree.Should().NotBeNull();
        tree.id.Should().Be(root.id);
        tree.Children.Should().NotBeEmpty();

        _output.WriteLine($"Tree root {tree.id}, children: {tree.Children.Count}");
    }

    [Fact]
    public async Task GetPathToRoot_ReturnsAncestors()
    {
        var svc = CreateService();
        var root = await svc.CreateGroupAsync("PathRoot", "organization");
        var dept = await svc.CreateChildGroupAsync(root.id, "PathDept", "department");
        var team = await svc.CreateChildGroupAsync(dept.id, "PathTeam", "team");

        var path = await svc.GetPathToRootAsync(team.id);

        path.Should().HaveCountGreaterOrEqualTo(2);
        path.Select(p => p.id).Should().Contain(root.id);
    }

    [Fact]
    public async Task MoveGroup_ChangesParent()
    {
        var svc = CreateService();
        var org1 = await svc.CreateGroupAsync("MoveOrg1", "organization");
        var org2 = await svc.CreateGroupAsync("MoveOrg2", "organization");
        var team = await svc.CreateChildGroupAsync(org1.id, "MoveTeam", "team");

        await svc.MoveGroupAsync(team.id, org2.id);

        var children1 = await svc.GetChildGroupsAsync(org1.id);
        var children2 = await svc.GetChildGroupsAsync(org2.id);

        children1.Should().NotContain(c => c.id == team.id);
        children2.Should().Contain(c => c.id == team.id);
    }

    // ── Membership ──────────────────────────────────────────────

    [Fact]
    public async Task AddMember_CreatesMembership()
    {
        var svc = CreateService();
        var group = await svc.CreateGroupAsync("MemberGroup", "team");
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        var member = await svc.AddMemberAsync(group.id, userId, "admin");

        member.Should().NotBeNull();
        member.id.Should().BeGreaterThan(0);
        member.key.Should().Be(userId);
        member.parent_id.Should().Be(group.id);
        member.Props.Role.Should().Be("admin");
        member.Props.JoinedAt.Should().NotBeNull();

        _output.WriteLine($"Added user {userId} to group {group.id} as admin");
    }

    [Fact]
    public async Task AddMember_Duplicate_Throws()
    {
        var svc = CreateService();
        var group = await svc.CreateGroupAsync("DupeMemberGroup", "team");
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        await svc.AddMemberAsync(group.id, userId);

        var act = () => svc.AddMemberAsync(group.id, userId);
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*already a member*");
    }

    [Fact]
    public async Task RemoveMember_DeletesMembership()
    {
        var svc = CreateService();
        var group = await svc.CreateGroupAsync("RemoveMemberGroup", "team");
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        await svc.AddMemberAsync(group.id, userId);
        await svc.RemoveMemberAsync(group.id, userId);

        var isMember = await svc.IsMemberAsync(group.id, userId);
        isMember.Should().BeFalse();
    }

    [Fact]
    public async Task UpdateMemberRole_ChangesRole()
    {
        var svc = CreateService();
        var group = await svc.CreateGroupAsync("RoleChangeGroup", "team");
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        await svc.AddMemberAsync(group.id, userId, "member");
        await svc.UpdateMemberRoleAsync(group.id, userId, "admin");

        var members = await svc.GetMembersAsync(group.id);
        members.Should().Contain(m => m.UserId == userId && m.Role == "admin");
    }

    [Fact]
    public async Task GetMembers_ReturnsGroupMembers()
    {
        var svc = CreateService();
        var group = await svc.CreateGroupAsync("ListMembersGroup", "team");
        var user1 = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var user2 = user1 + 1;

        await svc.AddMemberAsync(group.id, user1, "admin");
        await svc.AddMemberAsync(group.id, user2, "member");

        var members = await svc.GetMembersAsync(group.id);

        members.Should().HaveCount(2);
        members.Should().Contain(m => m.UserId == user1 && m.Role == "admin");
        members.Should().Contain(m => m.UserId == user2 && m.Role == "member");
    }

    [Fact]
    public async Task GetUserGroups_ReturnsUserMemberships()
    {
        var svc = CreateService();
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        var group1 = await svc.CreateGroupAsync("UserGroup1", "team");
        var group2 = await svc.CreateGroupAsync("UserGroup2", "department");

        await svc.AddMemberAsync(group1.id, userId, "member");
        await svc.AddMemberAsync(group2.id, userId, "admin");

        var groups = await svc.GetUserGroupsAsync(userId);

        groups.Should().HaveCountGreaterOrEqualTo(2);
        groups.Should().Contain(g => g.GroupId == group1.id && g.Role == "member");
        groups.Should().Contain(g => g.GroupId == group2.id && g.Role == "admin");
    }

    [Fact]
    public async Task IsMember_ReturnsTrueForActiveMember()
    {
        var svc = CreateService();
        var group = await svc.CreateGroupAsync("IsMemberGroup", "team");
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        await svc.AddMemberAsync(group.id, userId);

        var result = await svc.IsMemberAsync(group.id, userId);
        result.Should().BeTrue();
    }

    [Fact]
    public async Task IsMember_ReturnsFalseForNonMember()
    {
        var svc = CreateService();
        var group = await svc.CreateGroupAsync("IsMemberFalseGroup", "team");
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        var result = await svc.IsMemberAsync(group.id, userId);
        result.Should().BeFalse();
    }

    [Fact]
    public async Task IsMember_ReturnsFalseForExpiredMembership()
    {
        var svc = CreateService();
        var group = await svc.CreateGroupAsync("ExpiredGroup", "team");
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        // Add with expiration in the past
        await svc.AddMemberAsync(group.id, userId, "member",
            expiresAt: DateTimeOffset.UtcNow.AddHours(-1));

        var result = await svc.IsMemberAsync(group.id, userId);
        result.Should().BeFalse();
    }

    // ── Role resolution ─────────────────────────────────────────

    [Fact]
    public async Task ResolveUserRoles_ReturnsActiveNonExpiredMemberships()
    {
        var svc = CreateService();
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        var active = await svc.CreateGroupAsync("ResolveActive", "role");
        var expired = await svc.CreateGroupAsync("ResolveExpired", "role");

        await svc.AddMemberAsync(active.id, userId, "member");
        await svc.AddMemberAsync(expired.id, userId, "member",
            expiresAt: DateTimeOffset.UtcNow.AddHours(-1));

        var roles = await svc.ResolveUserRolesAsync(userId);

        roles.Should().Contain(r => r.GroupId == active.id);
        roles.Should().NotContain(r => r.GroupId == expired.id);
    }

    [Fact]
    public async Task ResolveUserRoles_IncludesGroupInfo()
    {
        var svc = CreateService();
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var group = await svc.CreateGroupAsync("ResolveInfo", "role");

        await svc.AddMemberAsync(group.id, userId, "admin");

        var roles = await svc.ResolveUserRolesAsync(userId);

        var entry = roles.FirstOrDefault(r => r.GroupId == group.id);
        entry.Should().NotBeNull();
        entry!.GroupName.Should().Be("ResolveInfo");
        entry.GroupType.Should().Be("role");
        entry.Role.Should().Be("admin");
    }

    // ── Ancestor membership ─────────────────────────────────────

    [Fact]
    public async Task IsMember_ViaAncestorGroup_ReturnsTrue()
    {
        var svc = CreateService();
        var org = await svc.CreateGroupAsync("AncOrg", "organization");
        var dept = await svc.CreateChildGroupAsync(org.id, "AncDept", "department");
        var team = await svc.CreateChildGroupAsync(dept.id, "AncTeam", "team");
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        // User is member of org (top-level)
        await svc.AddMemberAsync(org.id, userId, "member");

        // Should be considered member of dept and team via ancestor traversal
        var isDeptMember = await svc.IsMemberAsync(dept.id, userId);
        var isTeamMember = await svc.IsMemberAsync(team.id, userId);

        isDeptMember.Should().BeTrue("member of ancestor org → member of dept");
        isTeamMember.Should().BeTrue("member of ancestor org → member of team");

        _output.WriteLine($"User {userId} in org {org.id}: dept={isDeptMember}, team={isTeamMember}");
    }

    [Fact]
    public async Task IsMember_ViaAncestorGroup_Expired_ReturnsFalse()
    {
        var svc = CreateService();
        var org = await svc.CreateGroupAsync("AncExpOrg", "organization");
        var team = await svc.CreateChildGroupAsync(org.id, "AncExpTeam", "team");
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        // Expired membership in ancestor
        await svc.AddMemberAsync(org.id, userId, "member",
            expiresAt: DateTimeOffset.UtcNow.AddHours(-1));

        var isTeamMember = await svc.IsMemberAsync(team.id, userId);
        isTeamMember.Should().BeFalse("expired ancestor membership should not count");
    }

    // ── Cascade delete ──────────────────────────────────────────

    [Fact]
    public async Task DeleteGroup_CascadesChildMemberships()
    {
        var svc = CreateService();
        var org = await svc.CreateGroupAsync("CascadeOrg", "organization");
        var dept = await svc.CreateChildGroupAsync(org.id, "CascadeDept", "department");
        var team = await svc.CreateChildGroupAsync(dept.id, "CascadeTeam", "team");

        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        await svc.AddMemberAsync(dept.id, userId, "lead");
        await svc.AddMemberAsync(team.id, userId, "member");

        // Delete the org (parent of dept and team)
        await svc.DeleteGroupAsync(org.id);

        // All memberships should be gone
        var userGroups = await svc.GetUserGroupsAsync(userId);
        userGroups.Should().NotContain(g => g.GroupId == dept.id);
        userGroups.Should().NotContain(g => g.GroupId == team.id);

        _output.WriteLine($"After cascade delete: user has {userGroups.Count} groups (none from deleted subtree)");
    }

    // ── Expired member filtering ────────────────────────────────

    [Fact]
    public async Task GetMembers_ExcludesExpiredMembers()
    {
        var svc = CreateService();
        var group = await svc.CreateGroupAsync("ExpFilterGroup", "team");
        var activeUser = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var expiredUser = activeUser + 1;

        await svc.AddMemberAsync(group.id, activeUser, "member");
        await svc.AddMemberAsync(group.id, expiredUser, "member",
            expiresAt: DateTimeOffset.UtcNow.AddHours(-1));

        var members = await svc.GetMembersAsync(group.id);

        members.Should().Contain(m => m.UserId == activeUser);
        members.Should().NotContain(m => m.UserId == expiredUser,
            "expired members should be filtered out");
    }

    [Fact]
    public async Task GetUserGroups_ExcludesExpiredMemberships()
    {
        var svc = CreateService();
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var active = await svc.CreateGroupAsync("UGActive", "team");
        var expired = await svc.CreateGroupAsync("UGExpired", "team");

        await svc.AddMemberAsync(active.id, userId, "member");
        await svc.AddMemberAsync(expired.id, userId, "member",
            expiresAt: DateTimeOffset.UtcNow.AddHours(-1));

        var groups = await svc.GetUserGroupsAsync(userId);

        groups.Should().Contain(g => g.GroupId == active.id);
        groups.Should().NotContain(g => g.GroupId == expired.id,
            "expired memberships should be filtered out");
    }

    // ── GetChildGroups ──────────────────────────────────────────

    [Fact]
    public async Task GetChildGroups_ReturnsOnlyDirectChildrenNotGrandchildren()
    {
        var svc = CreateService();
        var root = await svc.CreateGroupAsync("OnlyDirectRoot", "organization");
        var child = await svc.CreateChildGroupAsync(root.id, "OnlyDirectChild", "department");
        var grandchild = await svc.CreateChildGroupAsync(child.id, "OnlyDirectGrandchild", "team");

        var children = await svc.GetChildGroupsAsync(root.id);

        children.Should().Contain(c => c.id == child.id);
        children.Should().NotContain(c => c.id == grandchild.id,
            "grandchildren should not appear in direct children list");
    }
}
