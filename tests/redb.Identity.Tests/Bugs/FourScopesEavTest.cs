using FluentAssertions;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.Bugs;

/// <summary>
/// Low-level reproduction: save/load AuthorizationProps with various scope counts.
/// Bypass OpenIddict and route error handlers to see raw PROPS exceptions.
/// </summary>
[Collection("Postgres")]
public class FourScopesPropsTest
{
    private readonly PostgresFixture _fx;
    private readonly ITestOutputHelper _output;

    public FourScopesPropsTest(PostgresFixture fx, ITestOutputHelper output)
    {
        _fx = fx;
        _output = output;
    }

    [Theory]
    [InlineData(new[] { "openid" }, "1 scope")]
    [InlineData(new[] { "openid", "profile" }, "2 scopes")]
    [InlineData(new[] { "openid", "profile", "email" }, "3 scopes")]
    [InlineData(new[] { "openid", "profile", "email", "phone" }, "4 scopes")]
    [InlineData(new[] { "openid", "profile", "email", "phone", "offline_access" }, "5 scopes")]
    public async Task SaveAndLoad_AuthorizationWithScopes(string[] scopes, string label)
    {
        _output.WriteLine($"Testing {label}: [{string.Join(", ", scopes)}]");

        // Create an authorization with the given scopes
        var auth = new RedbObject<AuthorizationProps>
        {
            key = 99999, // dummy user id
            Props = new AuthorizationProps
            {
                ApplicationObjectId = 1,
                Status = "valid",
                Type = "ad-hoc",
                Scopes = scopes,
                Properties = new Dictionary<string, string>
                {
                    ["creation_date"] = DateTimeOffset.UtcNow.ToString("O")
                }
            }
        };

        try
        {
            // Save
            var id = await _fx.Redb.SaveAsync(auth);
            _output.WriteLine($"  Saved with id={id}");
            id.Should().BeGreaterThan(0);

            // Load
            var loaded = await _fx.Redb.LoadAsync<AuthorizationProps>(id);
            _output.WriteLine($"  Loaded: Scopes=[{string.Join(", ", loaded?.Props.Scopes ?? [])}]");
            loaded.Should().NotBeNull();
            loaded!.Props.Scopes.Should().BeEquivalentTo(scopes);

            // Query
            var queried = await _fx.Redb.Query<AuthorizationProps>()
                .WhereRedb(o => o.Key == 99999)
                .Where(a => a.Status == "valid")
                .Where(a => a.Type == "ad-hoc")
                .ToListAsync();
            _output.WriteLine($"  Query returned {queried.Count} results");
            queried.Should().Contain(a => a.id == id);

            // Cleanup
            await _fx.Redb.DeleteAsync(id);
            _output.WriteLine($"  Cleaned up");
        }
        catch (Exception ex)
        {
            _output.WriteLine($"  FAILED: {ex.GetType().Name}: {ex.Message}");
            var inner = ex.InnerException;
            while (inner != null)
            {
                _output.WriteLine($"  Inner: {inner.GetType().Name}: {inner.Message}");
                inner = inner.InnerException;
            }
            throw;
        }
    }

    [Fact]
    public async Task SaveAndLoad_AuthorizationWithFourScopes_NoProperties()
    {
        // Test whether Properties dict contributes to the problem
        var auth = new RedbObject<AuthorizationProps>
        {
            key = 99998,
            Props = new AuthorizationProps
            {
                ApplicationObjectId = 1,
                Status = "valid",
                Type = "ad-hoc",
                Scopes = new[] { "openid", "profile", "email", "phone" },
                Properties = null // No properties
            }
        };

        var id = await _fx.Redb.SaveAsync(auth);
        _output.WriteLine($"Saved 4 scopes (no properties) with id={id}");

        var loaded = await _fx.Redb.LoadAsync<AuthorizationProps>(id);
        loaded.Should().NotBeNull();
        loaded!.Props.Scopes.Should().BeEquivalentTo("openid", "profile", "email", "phone");

        await _fx.Redb.DeleteAsync(id);
    }
}
