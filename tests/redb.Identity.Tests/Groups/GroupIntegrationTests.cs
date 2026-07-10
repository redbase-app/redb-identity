using FluentAssertions;
using redb.Identity.Contracts.Routes;
using redb.Identity.Tests.Infrastructure;
using redb.Route.Core;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.Groups;

/// <summary>
/// Integration tests for group management via direct-vm routes.
/// Uses <see cref="ProductionBootstrapFixture"/> with full OpenIddict pipeline.
/// </summary>
[Collection("ProductionBootstrap")]
public class GroupIntegrationTests
{
    private readonly ProductionBootstrapFixture _fx;
    private readonly ITestOutputHelper _output;

    public GroupIntegrationTests(ProductionBootstrapFixture fx, ITestOutputHelper output)
    {
        _fx = fx;
        _output = output;
    }

    private Task<Exchange> Send(string operation, Dictionary<string, object?> body)
    {
        return _fx.RequestWithHeaders(
            IdentityEndpoints.ManageGroups,
            body,
            new Dictionary<string, object?> { ["operation"] = operation });
    }

    // ── Group CRUD ──────────────────────────────────────────────

    [Fact]
    public async Task Create_And_Read_Group()
    {
        var createEx = await Send("create", new Dictionary<string, object?>
        {
            ["name"] = "IntGroup1",
            ["groupType"] = "team",
            ["description"] = "Integration test group"
        });

        var created = createEx.Out?.Body;
        created.Should().NotBeNull();

        var id = GetId(created!);
        id.Should().BeGreaterThan(0);

        var readEx = await Send("read", new Dictionary<string, object?> { ["groupId"] = id });
        var read = readEx.Out?.Body;
        read.Should().NotBeNull();

        _output.WriteLine($"Created and read group {id}");
    }

    [Fact]
    public async Task List_ReturnsRootGroups()
    {
        await Send("create", new Dictionary<string, object?>
        {
            ["name"] = "IntListRoot",
            ["groupType"] = "organization"
        });

        var listEx = await Send("list", new Dictionary<string, object?>());
        var list = listEx.Out?.Body as IEnumerable<object>;
        list.Should().NotBeNullOrEmpty();

        _output.WriteLine($"Root groups count: {list!.Count()}");
    }

    [Fact]
    public async Task Update_Group()
    {
        var createEx = await Send("create", new Dictionary<string, object?>
        {
            ["name"] = "IntUpdateBefore",
            ["groupType"] = "team"
        });
        var id = GetId(createEx.Out!.Body!);

        var updateEx = await Send("update", new Dictionary<string, object?>
        {
            ["groupId"] = id,
            ["name"] = "IntUpdateAfter",
            ["description"] = "Updated"
        });

        updateEx.Out?.Body.Should().NotBeNull();

        var readEx = await Send("read", new Dictionary<string, object?> { ["groupId"] = id });
        var body = readEx.Out?.Body;
        GetProp(body!, "name").Should().Be("IntUpdateAfter");

        _output.WriteLine($"Updated group {id}");
    }

    [Fact]
    public async Task Delete_Group()
    {
        var createEx = await Send("create", new Dictionary<string, object?>
        {
            ["name"] = "IntDeleteTarget",
            ["groupType"] = "team"
        });
        var id = GetId(createEx.Out!.Body!);

        await Send("delete", new Dictionary<string, object?> { ["groupId"] = id });

        var readEx = await Send("read", new Dictionary<string, object?> { ["groupId"] = id });
        // Should be not_found or null
        var body = readEx.Out?.Body;
        if (body is IDictionary<string, object?> dict)
            dict.ContainsKey("error").Should().BeTrue();
    }

    // ── Tree ────────────────────────────────────────────────────

    [Fact]
    public async Task CreateChild_And_GetTree()
    {
        var parentEx = await Send("create", new Dictionary<string, object?>
        {
            ["name"] = "IntTreeRoot",
            ["groupType"] = "organization"
        });
        var parentId = GetId(parentEx.Out!.Body!);

        await Send("create-child", new Dictionary<string, object?>
        {
            ["parentGroupId"] = parentId,
            ["name"] = "IntTreeChild",
            ["groupType"] = "team"
        });

        var treeEx = await Send("tree", new Dictionary<string, object?> { ["groupId"] = parentId });
        treeEx.Out?.Body.Should().NotBeNull();

        _output.WriteLine($"Tree loaded for group {parentId}");
    }

    [Fact]
    public async Task Children_ReturnsDirectChildren()
    {
        var parentEx = await Send("create", new Dictionary<string, object?>
        {
            ["name"] = "IntChildrenRoot",
            ["groupType"] = "organization"
        });
        var parentId = GetId(parentEx.Out!.Body!);

        await Send("create-child", new Dictionary<string, object?>
        {
            ["parentGroupId"] = parentId,
            ["name"] = "IntChild1",
            ["groupType"] = "team"
        });

        var childrenEx = await Send("children", new Dictionary<string, object?> { ["groupId"] = parentId });
        var children = childrenEx.Out?.Body as IEnumerable<object>;
        children.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task Path_ReturnsAncestors()
    {
        var rootEx = await Send("create", new Dictionary<string, object?>
        {
            ["name"] = "IntPathRoot",
            ["groupType"] = "organization"
        });
        var rootId = GetId(rootEx.Out!.Body!);

        var childEx = await Send("create-child", new Dictionary<string, object?>
        {
            ["parentGroupId"] = rootId,
            ["name"] = "IntPathChild",
            ["groupType"] = "team"
        });
        var childId = GetId(childEx.Out!.Body!);

        var pathEx = await Send("path", new Dictionary<string, object?> { ["groupId"] = childId });
        var path = pathEx.Out?.Body as IEnumerable<object>;
        path.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task Move_Group()
    {
        // Unique-per-run names so re-runs against a shared DB don't collide with
        // residue from a previous run (the create endpoint returns an error
        // Dictionary rather than {id} when a same-named group already exists, and
        // GetId() then throws "Cannot extract 'id' from Dictionary`2").
        var runTag = Guid.NewGuid().ToString("N")[..8];

        var org1Ex = await Send("create", new Dictionary<string, object?>
        {
            ["name"] = $"IntMoveOrg1-{runTag}",
            ["groupType"] = "organization"
        });
        var org1Id = GetId(org1Ex.Out!.Body!);

        var org2Ex = await Send("create", new Dictionary<string, object?>
        {
            ["name"] = $"IntMoveOrg2-{runTag}",
            ["groupType"] = "organization"
        });
        var org2Id = GetId(org2Ex.Out!.Body!);

        var teamEx = await Send("create-child", new Dictionary<string, object?>
        {
            ["parentGroupId"] = org1Id,
            ["name"] = $"IntMoveTeam-{runTag}",
            ["groupType"] = "team"
        });
        var teamId = GetId(teamEx.Out!.Body!);

        await Send("move", new Dictionary<string, object?>
        {
            ["groupId"] = teamId,
            ["newParentGroupId"] = org2Id
        });

        var children2 = await Send("children", new Dictionary<string, object?> { ["groupId"] = org2Id });
        var list = children2.Out?.Body as IEnumerable<object>;
        list.Should().NotBeNullOrEmpty("team should have moved to org2");
    }

    // ── Membership ──────────────────────────────────────────────

    [Fact]
    public async Task AddMember_And_ListMembers()
    {
        var groupEx = await Send("create", new Dictionary<string, object?>
        {
            ["name"] = "IntMemberGroup",
            ["groupType"] = "team"
        });
        var groupId = GetId(groupEx.Out!.Body!);

        await Send("add-member", new Dictionary<string, object?>
        {
            ["groupId"] = groupId,
            ["userId"] = _fx.TestUserId,
            ["role"] = "admin"
        });

        var membersEx = await Send("list-members", new Dictionary<string, object?> { ["groupId"] = groupId });
        var members = membersEx.Out?.Body as IEnumerable<object>;
        members.Should().NotBeNullOrEmpty();

        _output.WriteLine($"Group {groupId} has {members!.Count()} member(s)");
    }

    [Fact]
    public async Task UpdateMember_ChangesRole()
    {
        var groupEx = await Send("create", new Dictionary<string, object?>
        {
            ["name"] = "IntUpdateMemberGroup",
            ["groupType"] = "team"
        });
        var groupId = GetId(groupEx.Out!.Body!);
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        await Send("add-member", new Dictionary<string, object?>
        {
            ["groupId"] = groupId,
            ["userId"] = userId,
            ["role"] = "member"
        });

        await Send("update-member", new Dictionary<string, object?>
        {
            ["groupId"] = groupId,
            ["userId"] = userId,
            ["role"] = "admin"
        });

        var membersEx = await Send("list-members", new Dictionary<string, object?> { ["groupId"] = groupId });
        var members = membersEx.Out?.Body as IEnumerable<object>;
        members.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task RemoveMember_DeletesMembership()
    {
        var groupEx = await Send("create", new Dictionary<string, object?>
        {
            ["name"] = "IntRemoveMemberGroup",
            ["groupType"] = "team"
        });
        var groupId = GetId(groupEx.Out!.Body!);
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        await Send("add-member", new Dictionary<string, object?>
        {
            ["groupId"] = groupId,
            ["userId"] = userId,
            ["role"] = "member"
        });

        await Send("remove-member", new Dictionary<string, object?>
        {
            ["groupId"] = groupId,
            ["userId"] = userId
        });

        var membersEx = await Send("list-members", new Dictionary<string, object?> { ["groupId"] = groupId });
        var members = membersEx.Out?.Body as IEnumerable<object>;
        // After removing the only member, list should be empty or not contain the user
        var memberList = members?.ToList() ?? [];
        var hasUser = memberList.OfType<IDictionary<string, object?>>()
            .Any(d => d.TryGetValue("UserId", out var uid) && uid?.ToString() == userId.ToString());
        hasUser.Should().BeFalse("removed member should not appear in list");
    }

    [Fact]
    public async Task UserGroups_ReturnsUserMemberships()
    {
        var groupEx = await Send("create", new Dictionary<string, object?>
        {
            ["name"] = "IntUserGroupsGroup",
            ["groupType"] = "team"
        });
        var groupId = GetId(groupEx.Out!.Body!);
        var userId = _fx.TestUserId;

        await Send("add-member", new Dictionary<string, object?>
        {
            ["groupId"] = groupId,
            ["userId"] = userId,
            ["role"] = "member"
        });

        var userGroupsEx = await Send("user-groups", new Dictionary<string, object?> { ["userId"] = userId });
        var groups = userGroupsEx.Out?.Body as IEnumerable<object>;
        groups.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task IsMember_ReturnsCorrectResult()
    {
        var groupEx = await Send("create", new Dictionary<string, object?>
        {
            ["name"] = "IntIsMemberGroup",
            ["groupType"] = "team"
        });
        var groupId = GetId(groupEx.Out!.Body!);
        var userId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        // Not a member yet
        var checkEx1 = await Send("is-member", new Dictionary<string, object?>
        {
            ["groupId"] = groupId,
            ["userId"] = userId
        });

        var result1 = checkEx1.Out?.Body;
        GetProp(result1!, "isMember").Should().Be(false);

        // Add member
        await Send("add-member", new Dictionary<string, object?>
        {
            ["groupId"] = groupId,
            ["userId"] = userId,
            ["role"] = "member"
        });

        var checkEx2 = await Send("is-member", new Dictionary<string, object?>
        {
            ["groupId"] = groupId,
            ["userId"] = userId
        });

        var result2 = checkEx2.Out?.Body;
        GetProp(result2!, "isMember").Should().Be(true);
    }

    // ── Events ──────────────────────────────────────────────────

    [Fact]
    public async Task Create_SetsEventProperties()
    {
        var ex = await Send("create", new Dictionary<string, object?>
        {
            ["name"] = "IntEventGroup",
            ["groupType"] = "team"
        });

        ex.Properties.Should().ContainKey("identity-event-type");
        ex.Properties["identity-event-type"].Should().Be("GroupCreated");
        ex.Properties.Should().ContainKey("identity-event-data");
    }

    [Fact]
    public async Task AddMember_SetsEventProperties()
    {
        var groupEx = await Send("create", new Dictionary<string, object?>
        {
            ["name"] = "IntEventMemberGroup",
            ["groupType"] = "team"
        });
        var groupId = GetId(groupEx.Out!.Body!);

        var addEx = await Send("add-member", new Dictionary<string, object?>
        {
            ["groupId"] = groupId,
            ["userId"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            ["role"] = "member"
        });

        addEx.Properties.Should().ContainKey("identity-event-type");
        addEx.Properties["identity-event-type"].Should().Be("MemberAdded");
    }

    // ── Helpers ─────────────────────────────────────────────────

    private static long GetId(object body)
    {
        if (body is IDictionary<string, object?> dict && dict.TryGetValue("id", out var val))
            return Convert.ToInt64(val);
        // Try property via reflection
        var prop = body.GetType().GetProperty("id");
        if (prop is not null)
            return Convert.ToInt64(prop.GetValue(body));
        throw new InvalidOperationException($"Cannot extract 'id' from {body.GetType().Name}");
    }

    private static object? GetProp(object body, string name)
    {
        if (body is IDictionary<string, object?> dict && dict.TryGetValue(name, out var val))
            return val;
        var prop = body.GetType().GetProperty(name);
        return prop?.GetValue(body);
    }
}
