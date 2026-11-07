using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;
using redb.Core;
using redb.Core.Models.Configuration;
using redb.Core.Extensions;
using redb.Core.Pro.Extensions;
using redb.Postgres.Pro.Extensions;
using redb.Identity.Core.Models;
using redb.Identity.DataProtection;

namespace redb.Identity.Tests.Infrastructure;

public class PostgresFixture : IAsyncLifetime
{
    public IRedbService Redb { get; private set; } = null!;
    public ServiceProvider Services { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        var config = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json")
            .Build();

        var cs = config.GetConnectionString("Postgres")
            ?? throw new InvalidOperationException("ConnectionStrings:Postgres not found in appsettings.json");

        var sc = new ServiceCollection();
        sc.AddLogging(b => b.AddConsole().SetMinimumLevel(LogLevel.Warning));
        sc.AddRedbForTests(cs);

        Services = sc.BuildServiceProvider();
        Redb = Services.GetRequiredService<IRedbService>();

        try { await Redb.InitializeAsync(ensureCreated: true); }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"InitializeAsync(ensureCreated:true) failed, falling back: {ex.GetType().Name}: {ex.Message}");
            await Redb.InitializeAsync();
        }

        await Redb.SyncSchemeAsync<ApplicationProps>();
        await Redb.SyncSchemeAsync<AuthorizationProps>();
        await Redb.SyncSchemeAsync<ScopeProps>();
        await Redb.SyncSchemeAsync<TokenProps>();
        await Redb.SyncSchemeAsync<UserProps>();
        await Redb.SyncSchemeAsync<DataProtectionKeyProps>();
        await Redb.SyncSchemeAsync<SessionProps>();
        await Redb.SyncSchemeAsync<MfaProps>();
        await Redb.SyncSchemeAsync<GroupProps>();
        await Redb.SyncSchemeAsync<GroupMemberProps>();

        await Redb.InitializeTypeRegistryAsync();

        // Fix btree index overflow for large Payload values (4+ scope tokens)
        await IndexFixHelper.FixValueStringIndexAsync(cs);
    }

    public async Task DisposeAsync()
    {
        if (Services is not null)
            await Services.DisposeAsync();
    }
}
