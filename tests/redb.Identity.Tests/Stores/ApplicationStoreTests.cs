using System.Collections.Immutable;
using System.Text.Json;
using FluentAssertions;
using Xunit;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;
using redb.Identity.Core.Stores;
using redb.Identity.Tests.Infrastructure;

namespace redb.Identity.Tests.Stores;

[Collection("Postgres")]
public class ApplicationStoreTests
{
    private readonly RedbApplicationStore _store;
    private readonly PostgresFixture _fixture;

    public ApplicationStoreTests(PostgresFixture fixture)
    {
        _fixture = fixture;
        _store = new RedbApplicationStore(fixture.Redb);
    }

    private static RedbObject<ApplicationProps> MakeApp(string clientId, string? name = null) =>
        new()
        {
            name = name ?? $"Test App {clientId}",
            Props = new ApplicationProps
            {
                ClientId = clientId,
                ClientType = "confidential",
                ConsentType = "explicit",
                ApplicationType = "web",
                Permissions = ["ept:token", "gt:authorization_code", "scp:openid"],
                RedirectUris = [$"https://{clientId}.example.com/callback"],
                PostLogoutRedirectUris = [$"https://{clientId}.example.com/logout"],
                Requirements = ["ft:pkce"]
            }
        };

    [Fact]
    public async Task CreateAsync_AssignsId()
    {
        var app = MakeApp($"create-test-{Guid.NewGuid():N}");

        await _store.CreateAsync(app, CancellationToken.None);

        app.id.Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task FindByIdAsync_ReturnsCreatedEntity()
    {
        var clientId = $"find-id-{Guid.NewGuid():N}";
        var app = MakeApp(clientId);
        await _store.CreateAsync(app, CancellationToken.None);

        var found = await _store.FindByIdAsync(app.id.ToString(), CancellationToken.None);

        found.Should().NotBeNull();
        found!.Props.ClientId.Should().Be(clientId);
        found.name.Should().Be(app.name);
    }

    [Fact]
    public async Task FindByIdAsync_InvalidId_ReturnsNull()
    {
        var found = await _store.FindByIdAsync("not-a-number", CancellationToken.None);
        found.Should().BeNull();
    }

    [Fact]
    public async Task FindByClientIdAsync_ReturnsCorrectApp()
    {
        var clientId = $"find-client-{Guid.NewGuid():N}";
        var app = MakeApp(clientId);
        await _store.CreateAsync(app, CancellationToken.None);

        var found = await _store.FindByClientIdAsync(clientId, CancellationToken.None);

        found.Should().NotBeNull();
        found!.id.Should().Be(app.id);
    }

    [Fact]
    public async Task FindByRedirectUriAsync_ReturnMatchingApps()
    {
        var clientId = $"redirect-{Guid.NewGuid():N}";
        var uri = $"https://{clientId}.example.com/callback";
        var app = MakeApp(clientId);
        await _store.CreateAsync(app, CancellationToken.None);

        var results = new List<RedbObject<ApplicationProps>>();
        await foreach (var r in _store.FindByRedirectUriAsync(uri, CancellationToken.None))
            results.Add(r);

        results.Should().Contain(r => r.id == app.id);
    }

    [Fact]
    public async Task FindByPostLogoutRedirectUriAsync_ReturnMatchingApps()
    {
        var clientId = $"postlogout-{Guid.NewGuid():N}";
        var uri = $"https://{clientId}.example.com/logout";
        var app = MakeApp(clientId);
        await _store.CreateAsync(app, CancellationToken.None);

        var results = new List<RedbObject<ApplicationProps>>();
        await foreach (var r in _store.FindByPostLogoutRedirectUriAsync(uri, CancellationToken.None))
            results.Add(r);

        results.Should().Contain(r => r.id == app.id);
    }

    [Fact]
    public async Task UpdateAsync_PersistsChanges()
    {
        var clientId = $"update-{Guid.NewGuid():N}";
        var app = MakeApp(clientId);
        await _store.CreateAsync(app, CancellationToken.None);

        // Reload to get fresh hash
        var loaded = (await _store.FindByIdAsync(app.id.ToString(), CancellationToken.None))!;
        loaded.Props.ClientType = "public";
        loaded.name = "Updated Name";
        await _store.UpdateAsync(loaded, CancellationToken.None);

        var updated = await _store.FindByIdAsync(app.id.ToString(), CancellationToken.None);
        updated!.Props.ClientType.Should().Be("public");
        updated.name.Should().Be("Updated Name");
    }

    [Fact]
    public async Task UpdateAsync_StaleHash_ThrowsConcurrencyException()
    {
        var clientId = $"concurrency-{Guid.NewGuid():N}";
        var app = MakeApp(clientId);
        await _store.CreateAsync(app, CancellationToken.None);

        // Load two copies
        var copy1 = (await _store.FindByIdAsync(app.id.ToString(), CancellationToken.None))!;
        var copy2 = (await _store.FindByIdAsync(app.id.ToString(), CancellationToken.None))!;

        // Update copy1 (changes hash in DB)
        copy1.Props.ClientType = "public";
        await _store.UpdateAsync(copy1, CancellationToken.None);

        // copy2 now has stale hash
        copy2.Props.ConsentType = "implicit";
        Func<Task> act = async () => await _store.UpdateAsync(copy2, CancellationToken.None);

        await act.Should().ThrowAsync<OpenIddict.Abstractions.OpenIddictExceptions.ConcurrencyException>();
    }

    [Fact]
    public async Task DeleteAsync_RemovesEntity()
    {
        var clientId = $"delete-{Guid.NewGuid():N}";
        var app = MakeApp(clientId);
        await _store.CreateAsync(app, CancellationToken.None);

        await _store.DeleteAsync(app, CancellationToken.None);

        var found = await _store.FindByIdAsync(app.id.ToString(), CancellationToken.None);
        found.Should().BeNull();
    }

    [Fact]
    public async Task CountAsync_IncludesCreatedEntities()
    {
        var before = await _store.CountAsync(CancellationToken.None);

        var app = MakeApp($"count-{Guid.NewGuid():N}");
        await _store.CreateAsync(app, CancellationToken.None);

        var after = await _store.CountAsync(CancellationToken.None);
        after.Should().BeGreaterThan(before);
    }

    [Fact]
    public async Task ListAsync_WithPaging_ReturnsSubset()
    {
        // Create a few apps
        for (int i = 0; i < 3; i++)
        {
            var a = MakeApp($"list-{Guid.NewGuid():N}");
            await _store.CreateAsync(a, CancellationToken.None);
        }

        var page = new List<RedbObject<ApplicationProps>>();
        await foreach (var r in _store.ListAsync(2, 0, CancellationToken.None))
            page.Add(r);

        page.Should().HaveCountLessOrEqualTo(2);
    }

    [Fact]
    public async Task GettersSetters_Roundtrip()
    {
        var app = await _store.InstantiateAsync(CancellationToken.None);
        var ct = CancellationToken.None;

        await _store.SetClientIdAsync(app, "roundtrip-client", ct);
        await _store.SetClientTypeAsync(app, "confidential", ct);
        await _store.SetConsentTypeAsync(app, "explicit", ct);
        await _store.SetDisplayNameAsync(app, "Roundtrip App", ct);
        await _store.SetApplicationTypeAsync(app, "web", ct);
        await _store.SetClientSecretAsync(app, "s3cret", ct);
        await _store.SetPermissionsAsync(app, ["ept:token", "scp:openid"], ct);
        await _store.SetRedirectUrisAsync(app, ["https://example.com/cb"], ct);
        await _store.SetPostLogoutRedirectUrisAsync(app, ["https://example.com/logout"], ct);
        await _store.SetRequirementsAsync(app, ["ft:pkce"], ct);

        (await _store.GetClientIdAsync(app, ct)).Should().Be("roundtrip-client");
        (await _store.GetClientTypeAsync(app, ct)).Should().Be("confidential");
        (await _store.GetConsentTypeAsync(app, ct)).Should().Be("explicit");
        (await _store.GetDisplayNameAsync(app, ct)).Should().Be("Roundtrip App");
        (await _store.GetApplicationTypeAsync(app, ct)).Should().Be("web");
        (await _store.GetClientSecretAsync(app, ct)).Should().Be("s3cret");
        (await _store.GetPermissionsAsync(app, ct)).Should().BeEquivalentTo(new[] { "ept:token", "scp:openid" });
        (await _store.GetRedirectUrisAsync(app, ct)).Should().BeEquivalentTo(new[] { "https://example.com/cb" });
        (await _store.GetPostLogoutRedirectUrisAsync(app, ct)).Should().BeEquivalentTo(new[] { "https://example.com/logout" });
        (await _store.GetRequirementsAsync(app, ct)).Should().BeEquivalentTo(new[] { "ft:pkce" });
    }

    [Fact]
    public async Task Properties_RoundTrip_PreservesTypes()
    {
        var ct = CancellationToken.None;
        var app = MakeApp($"props-roundtrip-{Guid.NewGuid():N}");
        await _store.CreateAsync(app, ct);

        // Set properties with various JsonElement types
        var properties = ImmutableDictionary.CreateBuilder<string, JsonElement>();
        properties["str"] = JsonSerializer.Deserialize<JsonElement>("\"hello\"");
        properties["num"] = JsonSerializer.Deserialize<JsonElement>("42");
        properties["bool"] = JsonSerializer.Deserialize<JsonElement>("true");
        properties["obj"] = JsonSerializer.Deserialize<JsonElement>("{\"nested\":1}");

        await _store.SetPropertiesAsync(app, properties.ToImmutable(), ct);
        await _store.UpdateAsync(app, ct);

        // Reload from DB
        var loaded = await _store.FindByIdAsync(app.id.ToString(), ct);
        var result = await _store.GetPropertiesAsync(loaded!, ct);

        result["str"].ValueKind.Should().Be(JsonValueKind.String);
        result["str"].GetString().Should().Be("hello");
        result["num"].ValueKind.Should().Be(JsonValueKind.Number);
        result["num"].GetInt32().Should().Be(42);
        result["bool"].ValueKind.Should().Be(JsonValueKind.True);
        result["obj"].ValueKind.Should().Be(JsonValueKind.Object);
        result["obj"].GetProperty("nested").GetInt32().Should().Be(1);
    }

    [Fact]
    public async Task Settings_And_Properties_AreSeparateFields()
    {
        var ct = CancellationToken.None;
        var app = MakeApp($"separate-fields-{Guid.NewGuid():N}");
        await _store.CreateAsync(app, ct);

        // Set Settings (string→string)
        await _store.SetSettingsAsync(app,
            ImmutableDictionary.CreateRange(new[]
            {
                new KeyValuePair<string, string>("theme", "dark")
            }), ct);

        // Set Properties (string→JsonElement)
        var properties = ImmutableDictionary.CreateBuilder<string, JsonElement>();
        properties["count"] = JsonSerializer.Deserialize<JsonElement>("99");
        await _store.SetPropertiesAsync(app, properties.ToImmutable(), ct);

        await _store.UpdateAsync(app, ct);

        // Reload
        var loaded = await _store.FindByIdAsync(app.id.ToString(), ct);

        var settings = await _store.GetSettingsAsync(loaded!, ct);
        settings.Should().ContainKey("theme").WhoseValue.Should().Be("dark");
        settings.Should().NotContainKey("count");

        var props = await _store.GetPropertiesAsync(loaded!, ct);
        props.Should().ContainKey("count");
        props["count"].GetInt32().Should().Be(99);
        props.Should().NotContainKey("theme");
    }
}
