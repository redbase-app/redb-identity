using System.Xml.Linq;
using AwesomeAssertions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Core.Services;
using redb.Identity.DataProtection;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.DataProtection;

/// <summary>
/// Up to 4.3 <c>PersistKeysToRedb</c> registered the repository in DI only, the key manager ignored it and
/// kept the key ring in the file system of the process user. These tests replay the upgrade: a "4.3
/// process" protects data with a file key ring, a "4.4 process" imports that ring into redb and reads the
/// data; later starts need no files at all.
/// </summary>
public sealed class FileKeyRingImportTests : IAsyncLifetime
{
    // Same application name and purposes as the Identity module (IdentityModuleHost, PropsSigningKeyStore).
    private const string ApplicationName = "redb.identity";
    private const string SigningKeyPurpose = "redb.identity.signing-keys.v1";

    private readonly string _fileRing = Path.Combine(Path.GetTempPath(), "redb-dp-import-" + Guid.NewGuid().ToString("N"));
    private string _pgCs = "";

    public Task InitializeAsync()
    {
        var config = new ConfigurationBuilder().AddJsonFile("appsettings.json").Build();
        _pgCs = config.GetConnectionString("Postgres")
            ?? throw new InvalidOperationException("ConnectionStrings:Postgres not found");
        Directory.CreateDirectory(_fileRing);
        return Task.CompletedTask;
    }

    public Task DisposeAsync()
    {
        try { Directory.Delete(_fileRing, recursive: true); } catch { /* best effort */ }
        return Task.CompletedTask;
    }

    [Fact]
    public async Task Upgrade_imports_the_file_ring_once_and_data_stays_readable_without_files()
    {
        // 4.3: the key ring lives in files; a TOTP secret and a signing key are protected with it.
        string protectedTotp, protectedSigningKey;
        using (var legacy = BuildLegacyProcess())
        {
            var dp = legacy.GetRequiredService<IDataProtectionProvider>();
            protectedTotp = new MfaSecretProtector(dp).Protect("JBSWY3DPEHPK3PXP");
            protectedSigningKey = dp.CreateProtector(SigningKeyPurpose).Protect("-----BEGIN PRIVATE KEY-----test");
        }
        AgeFileRing();
        var fileKeyIds = Directory.EnumerateFiles(_fileRing, "key-*.xml")
            .Select(f => XElement.Load(f).Attribute("id")!.Value).ToList();
        fileKeyIds.Should().NotBeEmpty("the 4.3 process must have written its key ring to the files");

        // (a) 4.4, first start: the file ring is imported into redb and the data is readable.
        await using (var upgraded = await StartProcessAsync(importFrom: _fileRing))
        {
            upgraded.Imported.Should().Be(fileKeyIds.Count);
            upgraded.Read(protectedTotp, protectedSigningKey);
            (await KeyIdsInRedbAsync(upgraded.Services)).Should().Contain(fileKeyIds);
        }

        // Another program sharing the directory (the Tsak worker, dashboard, Identity Web) writes a key of
        // its own after the move: it is not Identity's and must not be imported.
        using (var other = BuildLegacyProcess())
            other.GetRequiredService<IKeyManager>().CreateNewKey(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(90));

        // (c) 4.4, next start with the same files: nothing is imported a second time.
        await using (var restarted = await StartProcessAsync(importFrom: _fileRing))
        {
            restarted.Imported.Should().Be(0);
            restarted.Read(protectedTotp, protectedSigningKey);
        }

        // (b) recreated container without the file volume: the ring comes from redb alone.
        Directory.Delete(_fileRing, recursive: true);
        await using (var recreated = await StartProcessAsync(importFrom: _fileRing))
        {
            recreated.Imported.Should().Be(0);
            recreated.Read(protectedTotp, protectedSigningKey);
        }
    }

    [Fact]
    public async Task New_keys_are_written_to_redb_not_to_the_file_system()
    {
        // (d) the key manager uses redb as its repository; a key it creates lands in redb.
        await using var process = await StartProcessAsync(importFrom: null);
        process.Services.GetRequiredService<IOptions<KeyManagementOptions>>().Value.XmlRepository
            .Should().BeOfType<RedbXmlRepository>();

        var keyManager = process.Services.GetRequiredService<IKeyManager>();
        var key = keyManager.CreateNewKey(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(90));

        (await KeyIdsInRedbAsync(process.Services)).Should().Contain(key.KeyId.ToString());
        process.Services.GetRequiredService<RedbXmlRepository>().GetAllElements()
            .Should().Contain(e => e.Attribute("id")!.Value == key.KeyId.ToString());
    }

    [Fact]
    public async Task Duplicate_rows_of_one_key_do_not_break_the_ring()
    {
        // Two nodes importing the same file key at once leave two rows; the key manager refuses a ring
        // with a duplicate key id, so the snapshot keeps one.
        string protectedTotp;
        using (var legacy = BuildLegacyProcess())
            protectedTotp = new MfaSecretProtector(legacy.GetRequiredService<IDataProtectionProvider>()).Protect("SECRET");

        AgeFileRing();
        var file = Directory.EnumerateFiles(_fileRing, "key-*.xml").Single();
        await using var process = await StartProcessAsync(importFrom: _fileRing);
        using (var scope = process.Services.CreateScope())
        {
            var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
            await redb.SaveAsync(new RedbObject<DataProtectionKeyProps>
            {
                name = Path.GetFileNameWithoutExtension(file),
                Props = new DataProtectionKeyProps
                {
                    FriendlyName = Path.GetFileNameWithoutExtension(file),
                    XmlContent = XElement.Load(file).ToString(SaveOptions.DisableFormatting)
                }
            });
            await process.Services.GetRequiredService<RedbXmlRepository>().ReloadAsync(redb);
        }

        var id = XElement.Load(file).Attribute("id")!.Value;
        process.Services.GetRequiredService<RedbXmlRepository>().GetAllElements()
            .Count(e => e.Attribute("id")?.Value == id).Should().Be(1);
        new MfaSecretProtector(process.Services.GetRequiredService<IDataProtectionProvider>())
            .Unprotect(protectedTotp).Should().Be("SECRET");
    }

    // ── helpers ──

    /// <summary>
    /// Dates the file keys back to 2020: a ring written by 4.3 predates the move of the ring into redb.
    /// The import keeps only elements older than that move, and on a shared test database the move may
    /// have been recorded by an earlier run.
    /// </summary>
    private void AgeFileRing()
    {
        foreach (var file in Directory.EnumerateFiles(_fileRing, "key-*.xml"))
        {
            var key = XElement.Load(file);
            key.Element("creationDate")!.Value = "2020-01-01T00:00:00Z";
            key.Save(file);
        }
    }

    private ServiceProvider BuildLegacyProcess()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDataProtection()
            .SetApplicationName(ApplicationName)
            .PersistKeysToFileSystem(new DirectoryInfo(_fileRing));
        return services.BuildServiceProvider();
    }

    /// <summary>A 4.4 process start: what the Identity init listener does before the first request.</summary>
    private async Task<UpgradedProcess> StartProcessAsync(string? importFrom)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddRedbForTests(_pgCs);
        services.AddDataProtection()
            .SetApplicationName(ApplicationName)
            .PersistKeysToRedb();
        var sp = services.BuildServiceProvider();

        using var scope = sp.CreateScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        await redb.InitializeAsync(ensureCreated: true);
        var imported = await RedbXmlRepository.ImportFileKeyRingsAsync(
            redb, importFrom is null ? [] : [importFrom], NullLogger.Instance);
        await sp.GetRequiredService<RedbXmlRepository>().ReloadAsync(redb);
        return new UpgradedProcess(sp, imported);
    }

    private static async Task<List<string>> KeyIdsInRedbAsync(IServiceProvider sp)
    {
        using var scope = sp.CreateScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var rows = await redb.Query<DataProtectionKeyProps>().ToListAsync();
        return rows
            .Select(r => r.Props.XmlContent is { Length: > 0 } xml ? XElement.Parse(xml).Attribute("id")?.Value : null)
            .Where(id => id is not null)
            .Select(id => id!)
            .ToList();
    }

    private sealed class UpgradedProcess(ServiceProvider services, int imported) : IAsyncDisposable
    {
        public ServiceProvider Services { get; } = services;
        public int Imported { get; } = imported;

        public void Read(string protectedTotp, string protectedSigningKey)
        {
            var dp = Services.GetRequiredService<IDataProtectionProvider>();
            new MfaSecretProtector(dp).Unprotect(protectedTotp).Should().Be("JBSWY3DPEHPK3PXP");
            dp.CreateProtector(SigningKeyPurpose).Unprotect(protectedSigningKey)
                .Should().Be("-----BEGIN PRIVATE KEY-----test");
        }

        public ValueTask DisposeAsync() => Services.DisposeAsync();
    }
}
