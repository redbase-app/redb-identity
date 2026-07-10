using Microsoft.Extensions.DependencyInjection;
using redb.Core.Extensions;
using redb.Core.Models.Configuration;
using redb.Core.Pro.Extensions;
// Provider extensions. Pro variants are tier-agnostic — they dispatch on
// AddRedb (Free) vs AddRedbPro (Pro). Do NOT also import the non-Pro
// extensions; the resulting overload set would be ambiguous.
using redb.Postgres.Pro.Extensions;
using redb.MSSql.Pro.Extensions;
using redb.SQLite.Pro.Extensions;
using redb.SQLite.Data;

namespace redb.Identity.Tests.Infrastructure;

/// <summary>
/// Test-only helper that wires redb to a (provider × tier) combination
/// chosen via two environment variables. Default: SQLite Pro with the
/// license bundled at <c>redb.license</c> in the test working dir.
/// <list type="bullet">
///   <item>
///     <c>REDB_PROVIDER</c> — picks storage. Values: <c>sqlite</c>
///     (default), <c>postgres</c>, <c>mssql</c>. Case-insensitive.
///   </item>
///   <item>
///     <c>REDB_USE_PRO</c> — picks tier. Default <c>true</c> (Pro);
///     set to <c>false</c> for the free
///     <see cref="PropsSaveStrategy.DeleteInsert"/> path.
///   </item>
/// </list>
/// Per-provider connection strings come from environment overrides if
/// set, otherwise from the local-dev defaults baked here. SQLite
/// auto-creates a unique temp-file database per call so parallel test
/// collections never collide.
/// </summary>
public static class TestRedbSetup
{
    public enum Provider { Sqlite, Postgres, MsSql }

    private static readonly Lazy<string?> LicenseToken = new(LoadLicenseToken);
    private static int _sqliteExtensionResolved;

    public static Provider SelectedProvider =>
        (Environment.GetEnvironmentVariable("REDB_PROVIDER")?.Trim().ToLowerInvariant()) switch
        {
            "postgres" or "pg" or "pgsql" => Provider.Postgres,
            "mssql" or "sqlserver" or "ms" => Provider.MsSql,
            _ => Provider.Sqlite,
        };

    public static bool UsePro =>
        !string.Equals(
            Environment.GetEnvironmentVariable("REDB_USE_PRO")?.Trim(),
            "false",
            StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Add redb to <paramref name="services"/>. The <paramref name="postgresConnString"/>
    /// is the historical local-dev default — used verbatim when REDB_PROVIDER=postgres
    /// and as a sentinel otherwise. SQLite / MSSQL pull their connection strings from
    /// env-var overrides or their respective defaults below.
    /// </summary>
    public static IServiceCollection AddRedbForTests(
        this IServiceCollection services,
        string postgresConnString,
        Action<RedbServiceConfiguration>? configure = null)
    {
        if (SelectedProvider == Provider.Sqlite)
            EnsureSqliteNativeExtensionResolved();

        if (UsePro)
        {
            return services.AddRedbPro(options =>
            {
                ApplyProvider(options, postgresConnString);
                ApplyLicense(options);
                options.Configure(c =>
                {
                    c.PropsSaveStrategy = PropsSaveStrategy.ChangeTracking;
                    c.EnableLazyLoadingForProps = false;
                    c.EnablePropsCache = false;
                    configure?.Invoke(c);
                });
            });
        }

        return services.AddRedb(options =>
        {
            ApplyProvider(options, postgresConnString);
            ApplyLicense(options);
            options.Configure(c =>
            {
                c.PropsSaveStrategy = PropsSaveStrategy.DeleteInsert;
                c.EnableLazyLoadingForProps = false;
                c.EnablePropsCache = false;
                configure?.Invoke(c);
            });
        });
    }

    private static void ApplyProvider(RedbOptionsBuilder options, string postgresConnString)
    {
        switch (SelectedProvider)
        {
            case Provider.Postgres:
                options.UsePostgres(ResolvePostgresConnectionString(postgresConnString));
                break;

            case Provider.MsSql:
                options.UseMsSql(ResolveMsSqlConnectionString());
                break;

            default:
                options.UseSqlite(ResolveSqliteConnectionString());
                break;
        }
    }

    private static void ApplyLicense(RedbOptionsBuilder options)
    {
        var token = LicenseToken.Value;
        if (!string.IsNullOrEmpty(token))
            options.WithLicense(token);
    }

    // ── Per-provider connection-string resolution ────────────────────────

    /// <summary>
    /// Resolves the Postgres connection string in this priority order:
    /// <list type="number">
    ///   <item><c>REDB_POSTGRES_CS</c> env var when set and non-empty;</item>
    ///   <item>the <paramref name="fallback"/> argument (typically
    ///   <c>config.GetConnectionString("Postgres")</c> read from
    ///   <c>appsettings.json</c>) when non-empty;</item>
    ///   <item>the local-dev default below — Max Pool Size=100 to match
    ///   MSSql/appsettings.json so the test-bench pool ceiling is uniform
    ///   across providers and survives <c>WithRedb</c>-per-scope amplification.</item>
    /// </list>
    /// The hardcoded default makes the same Host/Port/credentials/database
    /// match the literal connection strings used by the Audit*IntegrationTests
    /// classes so a test that drops below appsettings.json (or one whose
    /// fixture doesn't load it) still lands on the same database.
    /// </summary>
    public static string ResolvePostgresConnectionString(string fallback) =>
        Environment.GetEnvironmentVariable("REDB_POSTGRES_CS")?.Trim() is { Length: > 0 } cs
            ? cs
            : !string.IsNullOrEmpty(fallback)
                ? fallback
                : "Host=localhost;Port=5432;Username=postgres;Password=1;Database=redb;Pooling=true;Maximum Pool Size=100;Include Error Detail=true";

    public static string ResolveMsSqlConnectionString() =>
        Environment.GetEnvironmentVariable("REDB_MSSQL_CS")?.Trim() is { Length: > 0 } cs
            ? cs
            // Max Pool Size=100 explicitly so the test-bench ceiling matches the PG
            // appsettings.json value; Microsoft.Data.SqlClient's default is also 100
            // but stating it makes the limit explicit when comparing logs across
            // providers and matches the WithRedb-per-scope amplification headroom.
            : "Server=127.0.0.1,1433;Database=redb;User Id=sa;Password=1;TrustServerCertificate=true;Command Timeout=600;Max Pool Size=100;";

    /// <summary>
    /// Synthesize a per-call unique SQLite database file under the temp dir
    /// so parallel xUnit collections never collide. Override via
    /// <c>REDB_SQLITE_CS</c> for a pinned path or <c>:memory:</c>. Use
    /// <see cref="CreateSqliteScratchPath"/> when a single test needs to
    /// share storage across multiple redb instances (multi-replica probes).
    /// </summary>
    public static string ResolveSqliteConnectionString()
    {
        var pinned = Environment.GetEnvironmentVariable("REDB_SQLITE_CS")?.Trim();
        if (!string.IsNullOrEmpty(pinned))
            return pinned;

        return BuildSqliteConnectionString(CreateSqliteScratchPath());
    }

    /// <summary>
    /// Allocate a new temp-file path for SQLite. Use the resulting path in
    /// <see cref="BuildSqliteConnectionString"/> twice (or more) when a test
    /// needs multiple redb instances pointing at the same physical DB.
    /// </summary>
    public static string CreateSqliteScratchPath() =>
        Path.Combine(Path.GetTempPath(), $"redb-test-identity.db");
//        Path.Combine(Path.GetTempPath(), $"redb-test-{Guid.NewGuid():N}.db");

    /// <summary>Compose a SQLite connection string from a file path with the
    /// per-test defaults (file-based, ReadWriteCreate, no shared cache —
    /// shared cache would break WAL's reader-during-writer guarantee).</summary>
    public static string BuildSqliteConnectionString(string filePath) =>
        $"Data Source={filePath};Mode=ReadWriteCreate";

    // ── SQLite native extension (Free path only; harmless on Pro) ────────

    /// <summary>
    /// Free SQLite needs the native extension on every connection
    /// (get_object_json / pvt_build_*_sql live inside it). Pro doesn't,
    /// but setting the path is harmless. Best-effort: honour
    /// REDB_SQLITE_EXTENSION if set, else walk parents looking for
    /// redb.SQLite/native/build/redb.{dll,so,dylib}. Runs once per
    /// process via interlocked flag.
    /// </summary>
    private static void EnsureSqliteNativeExtensionResolved()
    {
        if (Interlocked.CompareExchange(ref _sqliteExtensionResolved, 1, 0) != 0) return;
        if (!string.IsNullOrEmpty(SqliteDataSource.NativeExtensionPath)) return;

        var fromEnv = Environment.GetEnvironmentVariable("REDB_SQLITE_EXTENSION")?.Trim();
        if (!string.IsNullOrEmpty(fromEnv) && File.Exists(fromEnv))
        {
            SqliteDataSource.NativeExtensionPath = fromEnv;
            return;
        }

        var suffix = OperatingSystem.IsWindows() ? ".dll"
                   : OperatingSystem.IsMacOS()   ? ".dylib"
                   : ".so";
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "redb.SQLite", "native", "build", "redb" + suffix);
            if (File.Exists(candidate))
            {
                SqliteDataSource.NativeExtensionPath = candidate;
                return;
            }
        }
    }

    // ── License loading ──────────────────────────────────────────────────

    /// <summary>
    /// Read the Pro license JWT from <c>redb.license</c> next to the test
    /// assembly. The file is shipped in the test project and copied to the
    /// output dir by the csproj. Missing file → null, callers proceed with
    /// the free tier.
    /// </summary>
    private static string? LoadLicenseToken()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "redb.license");
        if (!File.Exists(path)) return null;
        try
        {
            var token = File.ReadAllText(path).Trim();
            return string.IsNullOrEmpty(token) ? null : token;
        }
        catch
        {
            return null;
        }
    }
}
