using System.Collections.Immutable;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Query;
using redb.Core.Models.Entities;

namespace redb.Identity.DataProtection;

/// <summary>
/// ASP.NET DataProtection XML key repository backed by redb PROPS storage.
/// Each key is stored as a <see cref="RedbObject{TProps}"/> of <see cref="DataProtectionKeyProps"/>.
/// <para>
/// <b>Snapshot pattern (A1):</b> <see cref="GetAllElements"/> returns an in-memory
/// <see cref="ImmutableArray{T}"/> snapshot — pure-sync, no I/O on the auth hot path
/// (called per <c>Protect/Unprotect</c>). The snapshot is seeded by a host-side init
/// listener (Core's <c>RedbXmlRepositoryInitListener</c>, or any facade-local equivalent)
/// in <c>OnContextStarting</c>, before any route processes its first exchange.
/// <see cref="StoreElement"/> is a rare write (key-ring rotation): it persists via a
/// fresh DI scope and updates the snapshot in-process via
/// <see cref="ImmutableInterlocked.Update{T,TArg}(ref ImmutableArray{T}, Func{ImmutableArray{T}, TArg, ImmutableArray{T}}, TArg)"/>.
/// </para>
/// <para>
/// <b>Lifetime:</b> registered as Singleton so it can be safely consumed by
/// <see cref="IXmlRepository"/> (resolved from the root container by <c>KeyManager</c>).
/// Persistence uses <see cref="IServiceScopeFactory"/> per call, so no Scoped
/// <see cref="IRedbService"/> is captured.
/// </para>
/// </summary>
public sealed class RedbXmlRepository : IXmlRepository
{
    private readonly IServiceScopeFactory _scopeFactory;
    private ImmutableArray<XElement> _snapshot = ImmutableArray<XElement>.Empty;

    public RedbXmlRepository(IServiceScopeFactory scopeFactory)
    {
        ArgumentNullException.ThrowIfNull(scopeFactory);
        _scopeFactory = scopeFactory;
    }

    /// <inheritdoc />
    public IReadOnlyCollection<XElement> GetAllElements() => _snapshot;

    /// <inheritdoc />
    public void StoreElement(XElement element, string friendlyName)
    {
        ArgumentNullException.ThrowIfNull(element);
        // Bridge sync IXmlRepository contract to async redb. NOT on the auth hot path:
        // StoreElement is invoked only at key-ring rotation (rare), so the GetAwaiter().GetResult()
        // here cannot starve the thread pool the way a per-request bridge would.
        StoreElementAsync(element, friendlyName).GetAwaiter().GetResult();
    }

    private async Task StoreElementAsync(XElement element, string friendlyName)
    {
        await using var scope = _scopeFactory.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();

        var obj = new RedbObject<DataProtectionKeyProps>
        {
            name = friendlyName,
            Props = new DataProtectionKeyProps
            {
                FriendlyName = friendlyName,
                XmlContent = element.ToString(SaveOptions.DisableFormatting)
            }
        };
        await redb.SaveAsync(obj).ConfigureAwait(false);

        // Optimistic in-process snapshot update — visible to subsequent GetAllElements calls
        // without waiting for a refresh round-trip. Other cluster nodes pick this key up on
        // their next refresh / restart.
        ImmutableInterlocked.Update(ref _snapshot, (s, e) => s.Add(e), element);
    }

    /// <summary>
    /// Replaces the in-memory snapshot wholesale. Called by the host-side init listener
    /// during context startup (and by any future periodic refresh route).
    /// </summary>
    /// <remarks>
    /// Uses a plain assignment: <see cref="ImmutableArray{T}"/> is a struct wrapping a single
    /// reference field, and reference-sized writes are atomic on all supported .NET runtimes,
    /// so readers of <see cref="_snapshot"/> always observe either the old or new array in
    /// full (no torn read). <see cref="Interlocked.Exchange{T}(ref T, T)"/> cannot be used
    /// here because it is constrained to reference types and primitives and throws
    /// <see cref="NotSupportedException"/> for value-type generics like <c>ImmutableArray</c>.
    /// </remarks>
    public void ReplaceSnapshot(ImmutableArray<XElement> newSnapshot)
        => _snapshot = newSnapshot;

    /// <summary>Upper bound of persisted elements loaded into the snapshot (most recent first).</summary>
    public const int MaxElements = 100;

    /// <summary>
    /// Reloads the snapshot from redb: the most recent <see cref="MaxElements"/> elements, one per key
    /// id. Two nodes importing the same key at the same moment can leave two rows for it, and the key
    /// manager refuses a ring with a duplicate key id, so duplicates are dropped here.
    /// </summary>
    /// <returns>The number of elements in the new snapshot.</returns>
    public async Task<int> ReloadAsync(IRedbService redb, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(redb);

        var rows = await redb.Query<DataProtectionKeyProps>()
            .OrderByDescendingRedb(o => o.DateCreate)
            .Take(MaxElements)
            .ToListAsync()
            .ConfigureAwait(false);

        var elements = ImmutableArray.CreateBuilder<XElement>(rows.Count);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var row in rows)
        {
            if (string.IsNullOrEmpty(row.Props.XmlContent))
                continue;
            var element = XElement.Parse(row.Props.XmlContent);
            if (seen.Add(IdentityOf(element)))
                elements.Add(element);
        }

        ReplaceSnapshot(elements.ToImmutable());
        return elements.Count;
    }

    /// <summary>
    /// Copies into redb the elements of file-system key rings that redb does not hold yet. Before
    /// <see cref="RedbDataProtectionBuilderExtensions.PersistKeysToRedb"/> set the key manager's
    /// repository, the key ring silently lived in the default directory of the process user, and
    /// everything protected so far (signing keys, MFA secrets, cookies) is encrypted with those keys.
    /// <para>
    /// Idempotent by key id: a key already in redb is skipped, so a later start imports nothing, and
    /// cluster nodes that each kept their own file ring each add theirs. Files are left in place. The
    /// XML is copied as stored, encrypted elements stay encrypted with their original decryptor.
    /// </para>
    /// </summary>
    /// <returns>The number of elements imported.</returns>
    public static async Task<int> ImportFileKeyRingsAsync(
        IRedbService redb, IEnumerable<string> directories, ILogger logger, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(redb);
        ArgumentNullException.ThrowIfNull(directories);
        ArgumentNullException.ThrowIfNull(logger);

        var dirs = directories
            .Where(d => !string.IsNullOrWhiteSpace(d))
            .Select(Path.GetFullPath)
            .Distinct(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal)
            .Where(Directory.Exists)
            .ToList();
        var cutoff = await GetImportCutoffAsync(redb).ConfigureAwait(false);
        if (dirs.Count == 0)
            return 0;

        var known = new HashSet<string>(StringComparer.Ordinal);
        var rows = await redb.Query<DataProtectionKeyProps>().ToListAsync().ConfigureAwait(false);
        foreach (var row in rows)
        {
            if (!string.IsNullOrEmpty(row.Props.XmlContent))
                known.Add(IdentityOf(XElement.Parse(row.Props.XmlContent)));
        }

        var total = 0;
        foreach (var dir in dirs)
        {
            var imported = 0;
            foreach (var file in Directory.EnumerateFiles(dir, "*.xml").Order(StringComparer.Ordinal))
            {
                ct.ThrowIfCancellationRequested();
                XElement element;
                try
                {
                    element = XElement.Load(file);
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex, "DataProtection key ring import: {File} is not readable XML, skipped", file);
                    continue;
                }

                // Written after the ring moved to redb: another program's key (the Tsak worker,
                // dashboard and Identity Web keep their rings in the same default directory).
                if (DateOf(element) is { } written && written >= cutoff)
                    continue;

                if (!known.Add(IdentityOf(element)))
                    continue;

                var friendlyName = Path.GetFileNameWithoutExtension(file);
                await redb.SaveAsync(new RedbObject<DataProtectionKeyProps>
                {
                    name = friendlyName,
                    Props = new DataProtectionKeyProps
                    {
                        FriendlyName = friendlyName,
                        XmlContent = element.ToString(SaveOptions.DisableFormatting)
                    }
                }).ConfigureAwait(false);
                imported++;
            }

            if (imported > 0)
            {
                logger.LogWarning(
                    "DataProtection key ring: imported {Count} element(s) from the file key ring {Directory} into redb. " +
                    "The key ring now lives in redb only; the files are no longer read or written and can be kept as a backup.",
                    imported, dir);
            }
            total += imported;
        }

        return total;
    }

    /// <summary>
    /// The moment the ring moved into redb (<see cref="DataProtectionKeyImportProps"/>), recorded on the
    /// first call against this database; the earliest record wins when nodes race.
    /// </summary>
    private static async Task<DateTimeOffset> GetImportCutoffAsync(IRedbService redb)
    {
        var first = await EarliestCutoffAsync(redb).ConfigureAwait(false);
        if (first is { } existing)
            return existing;

        await redb.SaveAsync(new RedbObject<DataProtectionKeyImportProps>
        {
            name = "dp-key-ring-in-redb",
            Props = new DataProtectionKeyImportProps { StartedAt = DateTimeOffset.UtcNow }
        }).ConfigureAwait(false);

        return await EarliestCutoffAsync(redb).ConfigureAwait(false) ?? DateTimeOffset.UtcNow;
    }

    private static async Task<DateTimeOffset?> EarliestCutoffAsync(IRedbService redb)
    {
        var rows = await redb.Query<DataProtectionKeyImportProps>().ToListAsync().ConfigureAwait(false);
        return rows.Count == 0 ? null : rows.Min(r => r.Props.StartedAt);
    }

    /// <summary>The creation date of a key, the revocation date of a revocation; null when absent.</summary>
    private static DateTimeOffset? DateOf(XElement element)
    {
        var date = element.Name.LocalName switch
        {
            "key" => element.Element("creationDate")?.Value,
            "revocation" => element.Element("revocationDate")?.Value,
            _ => null
        };
        return DateTimeOffset.TryParse(date, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.RoundtripKind, out var parsed) ? parsed : null;
    }

    /// <summary>A key is identified by its id; any other element (a revocation) by its exact XML.</summary>
    private static string IdentityOf(XElement element)
        => element.Name.LocalName == "key" && element.Attribute("id")?.Value is { Length: > 0 } id
            ? "key:" + id.ToLowerInvariant()
            : "xml:" + element.ToString(SaveOptions.DisableFormatting);
}

/// <summary>
/// Where ASP.NET Core DataProtection keeps its key ring when no repository is configured, for the
/// one-off import into <see cref="RedbXmlRepository"/>. Mirrors the framework's internal
/// <c>DefaultKeyStorageDirectories</c> (aspnetcore v10.0.13): the Azure App Service location, then
/// <c>%LOCALAPPDATA%\ASP.NET\DataProtection-Keys</c> on Windows (or when <c>LOCALAPPDATA</c> is set),
/// otherwise <c>$HOME/.aspnet/DataProtection-Keys</c>.
/// </summary>
public static class DefaultFileKeyRing
{
    private const string FolderName = "DataProtection-Keys";

    /// <summary>The default file key ring directories of the current process, existing or not.</summary>
    public static IReadOnlyList<string> Directories()
    {
        var result = new List<string>();

        if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("WEBSITE_INSTANCE_ID")) &&
            Environment.GetEnvironmentVariable("HOME") is { Length: > 0 } azureHome)
        {
            result.Add(Path.Combine(azureHome, "ASP.NET", FolderName));
        }

        var localAppDataSystem = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var localAppDataEnv = Environment.GetEnvironmentVariable("LOCALAPPDATA");
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        if (OperatingSystem.IsWindows() && !string.IsNullOrEmpty(localAppDataSystem))
            result.Add(Path.Combine(localAppDataSystem, "ASP.NET", FolderName));
        else if (localAppDataEnv is not null)
            result.Add(Path.Combine(localAppDataEnv, "ASP.NET", FolderName));
        else if (!string.IsNullOrEmpty(home))
            result.Add(OperatingSystem.IsWindows()
                ? Path.Combine(home, "AppData", "Local", "ASP.NET", FolderName)
                : Path.Combine(home, ".aspnet", FolderName));
        else if (!string.IsNullOrEmpty(localAppDataSystem))
            result.Add(Path.Combine(localAppDataSystem, "ASP.NET", FolderName));

        return result;
    }
}
