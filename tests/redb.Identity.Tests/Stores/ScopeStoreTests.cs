using System.Collections.Immutable;
using FluentAssertions;
using Xunit;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;
using redb.Identity.Core.Stores;
using redb.Identity.Tests.Infrastructure;

namespace redb.Identity.Tests.Stores;

[Collection("Postgres")]
public class ScopeStoreTests
{
    private readonly RedbScopeStore _store;

    public ScopeStoreTests(PostgresFixture fixture)
    {
        _store = new RedbScopeStore(fixture.Redb);
    }

    private static RedbObject<ScopeProps> MakeScope(string scopeName) =>
        new()
        {
            name = $"Display: {scopeName}",
            Props = new ScopeProps
            {
                ScopeName = scopeName,
                Description = $"Scope {scopeName}",
                Resources = [$"api-{scopeName}"]
            }
        };

    [Fact]
    public async Task CreateAsync_AssignsId()
    {
        var scope = MakeScope($"create-{Guid.NewGuid():N}");
        await _store.CreateAsync(scope, CancellationToken.None);
        scope.id.Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task FindByIdAsync_ReturnsCreatedEntity()
    {
        var scopeName = $"find-id-{Guid.NewGuid():N}";
        var scope = MakeScope(scopeName);
        await _store.CreateAsync(scope, CancellationToken.None);

        var found = await _store.FindByIdAsync(scope.id.ToString(), CancellationToken.None);
        found.Should().NotBeNull();
        found!.Props.ScopeName.Should().Be(scopeName);
    }

    [Fact]
    public async Task FindByNameAsync_ReturnsCorrectScope()
    {
        var scopeName = $"find-name-{Guid.NewGuid():N}";
        var scope = MakeScope(scopeName);
        await _store.CreateAsync(scope, CancellationToken.None);

        var found = await _store.FindByNameAsync(scopeName, CancellationToken.None);
        found.Should().NotBeNull();
        found!.id.Should().Be(scope.id);
    }

    [Fact]
    public async Task FindByNamesAsync_ReturnsMultiple()
    {
        var name1 = $"names-a-{Guid.NewGuid():N}";
        var name2 = $"names-b-{Guid.NewGuid():N}";
        var s1 = MakeScope(name1);
        var s2 = MakeScope(name2);
        await _store.CreateAsync(s1, CancellationToken.None);
        await _store.CreateAsync(s2, CancellationToken.None);

        var results = new List<RedbObject<ScopeProps>>();
        await foreach (var r in _store.FindByNamesAsync(
            ImmutableArray.Create(name1, name2), CancellationToken.None))
            results.Add(r);

        results.Should().HaveCount(2);
        results.Select(r => r.Props.ScopeName).Should().BeEquivalentTo(new[] { name1, name2 });
    }

    [Fact]
    public async Task FindByResourceAsync_ReturnsMatchingScopes()
    {
        var scopeName = $"resource-{Guid.NewGuid():N}";
        var resource = $"api-{scopeName}";
        var scope = MakeScope(scopeName);
        await _store.CreateAsync(scope, CancellationToken.None);

        var results = new List<RedbObject<ScopeProps>>();
        await foreach (var r in _store.FindByResourceAsync(resource, CancellationToken.None))
            results.Add(r);

        results.Should().Contain(r => r.id == scope.id);
    }

    [Fact]
    public async Task UpdateAsync_PersistsChanges()
    {
        var scopeName = $"update-{Guid.NewGuid():N}";
        var scope = MakeScope(scopeName);
        await _store.CreateAsync(scope, CancellationToken.None);

        var loaded = (await _store.FindByIdAsync(scope.id.ToString(), CancellationToken.None))!;
        loaded.Props.Description = "Updated description";
        await _store.UpdateAsync(loaded, CancellationToken.None);

        var updated = await _store.FindByIdAsync(scope.id.ToString(), CancellationToken.None);
        updated!.Props.Description.Should().Be("Updated description");
    }

    [Fact]
    public async Task DeleteAsync_RemovesEntity()
    {
        var scope = MakeScope($"delete-{Guid.NewGuid():N}");
        await _store.CreateAsync(scope, CancellationToken.None);
        await _store.DeleteAsync(scope, CancellationToken.None);

        var found = await _store.FindByIdAsync(scope.id.ToString(), CancellationToken.None);
        found.Should().BeNull();
    }

    [Fact]
    public async Task CountAsync_IncludesCreatedEntities()
    {
        var before = await _store.CountAsync(CancellationToken.None);
        var scope = MakeScope($"count-{Guid.NewGuid():N}");
        await _store.CreateAsync(scope, CancellationToken.None);
        var after = await _store.CountAsync(CancellationToken.None);
        after.Should().BeGreaterThan(before);
    }

    [Fact]
    public async Task GettersSetters_Roundtrip()
    {
        var scope = await _store.InstantiateAsync(CancellationToken.None);
        var ct = CancellationToken.None;

        await _store.SetNameAsync(scope, "test-scope", ct);
        await _store.SetDisplayNameAsync(scope, "Test Scope Display", ct);
        await _store.SetDescriptionAsync(scope, "A test scope", ct);
        await _store.SetResourcesAsync(scope, ImmutableArray.Create("api1", "api2"), ct);

        (await _store.GetNameAsync(scope, ct)).Should().Be("test-scope");
        (await _store.GetDisplayNameAsync(scope, ct)).Should().Be("Test Scope Display");
        (await _store.GetDescriptionAsync(scope, ct)).Should().Be("A test scope");
        (await _store.GetResourcesAsync(scope, ct)).Should().BeEquivalentTo(new[] { "api1", "api2" });
    }
}
