using System.Xml.Linq;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using redb.Core;
using redb.Identity.Core.DataProtection;
using redb.Identity.DataProtection;
using redb.Identity.Tests.Infrastructure;

namespace redb.Identity.Tests.Stores;

[Collection("Postgres")]
public class XmlRepositoryTests
{
    private readonly RedbXmlRepository _repo;
    private readonly IServiceScopeFactory _scopeFactory;

    public XmlRepositoryTests(PostgresFixture fixture)
    {
        // Use the fixture's own ServiceProvider so each scope.GetRequiredService<IRedbService>()
        // gets a fresh Scoped IRedbService with its own connection — required for the
        // concurrency test below (otherwise all writers serialize on a single connection).
        _scopeFactory = fixture.Services.GetRequiredService<IServiceScopeFactory>();
        _repo = new RedbXmlRepository(_scopeFactory);
    }

    [Fact]
    public void StoreElement_ThenGetAllElements_RoundTrips()
    {
        var keyId = Guid.NewGuid().ToString();
        var xml = new XElement("key",
            new XAttribute("id", keyId),
            new XElement("value", "secret-data"));

        _repo.StoreElement(xml, $"key-{keyId}");

        var all = _repo.GetAllElements();
        all.Should().Contain(e =>
            e.Attribute("id")!.Value == keyId &&
            e.Element("value")!.Value == "secret-data");
    }

    [Fact]
    public void StoreMultipleElements_AllReturned()
    {
        var id1 = Guid.NewGuid().ToString();
        var id2 = Guid.NewGuid().ToString();

        _repo.StoreElement(new XElement("key", new XAttribute("id", id1)), $"key-{id1}");
        _repo.StoreElement(new XElement("key", new XAttribute("id", id2)), $"key-{id2}");

        var all = _repo.GetAllElements();
        all.Should().Contain(e => e.Attribute("id")!.Value == id1);
        all.Should().Contain(e => e.Attribute("id")!.Value == id2);
    }

    /// <summary>
    /// G1 — Concurrent <c>StoreElement</c> + <c>GetAllElements</c> must not throw and must
    /// preserve every stored element. Snapshot is updated via <c>ImmutableInterlocked.Update</c>;
    /// readers always see a consistent immutable view.
    /// </summary>
    [Fact]
    public async Task ConcurrentStoreAndRead_NoLossNoException()
    {
        const int writers = 16;
        const int readers = 32;
        var ids = Enumerable.Range(0, writers).Select(_ => Guid.NewGuid().ToString()).ToArray();

        var writeTasks = ids.Select(id => Task.Run(() =>
            _repo.StoreElement(new XElement("key", new XAttribute("id", id)), $"key-{id}")));

        // Readers spam GetAllElements while writers are inserting — assertions below check
        // that no read observes a partially-applied snapshot (would manifest as exceptions
        // from ImmutableArray enumeration, or as null Attribute lookups).
        var readTasks = Enumerable.Range(0, readers).Select(__ => Task.Run(() =>
        {
            for (int i = 0; i < 32; i++)
            {
                var snap = _repo.GetAllElements();
                foreach (var el in snap)
                {
                    var ignored = el.Attribute("id")?.Value;
                }
            }
        }));

        await Task.WhenAll(writeTasks.Concat(readTasks));

        var final = _repo.GetAllElements();
        foreach (var id in ids)
            final.Should().Contain(e => e.Attribute("id")!.Value == id,
                $"writer for {id} must have its element visible after all writers complete");
    }
}
