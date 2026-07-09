using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Query;
using redb.Route.Abstractions;
using redb.Route.RedbCore.Models;

namespace redb.Identity.Core.Module;

/// <summary>
/// Creates / migrates the flat <c>identity_audit_log</c> relational table that
/// backs <c>GET /api/v1/identity/audit</c> and the user-detail Audit tab.
///
/// <para>
/// Architectural note. The audit pipeline used to persist events as
/// <c>AuditEventProps</c> rows in <c>_objects</c> + <c>_values</c>. That worked
/// but bloated the redb store with append-only flat data and turned trivial
/// "events for user X" queries into PVT scans. The relational table reverses
/// the trade-off: one row per event, indexed by <c>(timestamp, event_type,
/// category, user_id, login)</c>. We still go through redb's <see cref="IRedbContext"/>
/// for connection / dialect / transaction management — only the storage shape
/// is plain SQL.
/// </para>
///
/// <para>
/// DDL ships as an embedded resource per dialect
/// (<c>sql/audit/{pg,mssql,sqlite}_create_table.sql</c>) so the .tpkg carries
/// the schema and operators don't need a side-channel migration script. All
/// scripts are idempotent: <c>CREATE TABLE IF NOT EXISTS</c> + per-index
/// <c>IF NOT EXISTS</c> guards.
/// </para>
///
/// <para>
/// Order: registered AFTER <see cref="IdentityUniqueIndexesInitListener"/> so
/// the base redb schema and per-scheme unique indexes are already live.
/// </para>
/// </summary>
internal sealed class IdentityAuditLogTableInitListener : IRouteLifecycleListener
{
    private readonly IServiceProvider _sp;

    public IdentityAuditLogTableInitListener(IServiceProvider sp) => _sp = sp;

    public async Task OnContextStarting(IRouteContext context, CancellationToken ct)
    {
        await using var scope = _sp.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var dialect = scope.ServiceProvider.GetRequiredService<ISqlDialect>();
        var logger = scope.ServiceProvider
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger<IdentityAuditLogTableInitListener>();

        var provider = dialect.ProviderName ?? "";
        var resourceName = provider switch
        {
            var p when string.Equals(p, "PostgreSQL", StringComparison.OrdinalIgnoreCase)
                => "redb.Identity.Core.sql.audit.pg_create_table.sql",
            var p when string.Equals(p, "MSSql", StringComparison.OrdinalIgnoreCase)
                       || string.Equals(p, "SqlServer", StringComparison.OrdinalIgnoreCase)
                => "redb.Identity.Core.sql.audit.mssql_create_table.sql",
            var p when string.Equals(p, "Sqlite", StringComparison.OrdinalIgnoreCase)
                       || string.Equals(p, "SQLite", StringComparison.OrdinalIgnoreCase)
                => "redb.Identity.Core.sql.audit.sqlite_create_table.sql",
            _ => null
        };

        if (resourceName is null)
        {
            logger.LogWarning(
                "redb.Identity: audit log table init skipped — unsupported dialect '{Provider}'", provider);
            return;
        }

        var sql = ReadEmbedded(resourceName);
        if (string.IsNullOrEmpty(sql))
        {
            logger.LogError(
                "redb.Identity: failed to read embedded DDL '{Resource}' — audit table NOT created.", resourceName);
            return;
        }

        try
        {
            await redb.Context.ExecuteAsync(sql).ConfigureAwait(false);
            logger.LogInformation(
                "redb.Identity: identity_audit_log ensured ({Provider}).", provider);
        }
        catch (Exception ex)
        {
            // Audit table absence is degraded mode, NOT a startup blocker —
            // the sink will fail per-event and log, but the rest of identity
            // is still serviceable.
            logger.LogError(ex,
                "redb.Identity: failed to ensure identity_audit_log on {Provider}. " +
                "Audit persistence will fail until the table is created manually.", provider);
        }
    }

    private static string? ReadEmbedded(string resourceName)
    {
        var asm = typeof(IdentityAuditLogTableInitListener).Assembly;
        using var stream = asm.GetManifestResourceStream(resourceName);
        if (stream is null) return null;
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}
