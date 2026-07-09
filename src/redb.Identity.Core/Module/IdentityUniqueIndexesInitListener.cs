using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Query;
using redb.Identity.Core.Models;
using redb.Route.Abstractions;
using redb.Route.RedbCore.Models;

namespace redb.Identity.Core.Module;

/// <summary>
/// Creates per-scheme partial unique indexes on <c>_objects</c> to close TOCTOU
/// races in Identity check-then-save paths (OAuth ClientId/Scope/ReferenceId,
/// MFA user uniqueness, OIDC-extension user uniqueness, idempotency keys).
///
/// Runs in <see cref="OnContextStarting"/> AFTER <see cref="IdentitySchemaInitListener"/>
/// has created the base redb tables. Eagerly synchronises each target scheme
/// (so its row exists in <c>_schemes</c> with a known Id), then issues
/// <c>CREATE UNIQUE INDEX IF NOT EXISTS</c> for each pair. DDL is idempotent —
/// re-running on an existing database is safe.
///
/// Each index is scoped to its own <c>_id_scheme</c> via a WHERE clause, so
/// user-defined Props extensions on <c>_users</c> (or any other object) are
/// NEVER affected, even when they legitimately reuse <c>_value_string</c> or
/// <c>_key</c> values.
///
/// <para>
/// MSSQL trade-off: <c>_objects._value_string</c> is NVARCHAR(MAX) which cannot
/// back a B-tree key on SQL Server. The three <c>_value_string</c>-based
/// indexes (ApplicationProps / ScopeProps / TokenProps) are therefore applied
/// only on PostgreSQL. On MSSQL those three check-then-save paths remain
/// application-level optimistic — a trade-off documented in STATUS.md.
/// </para>
///
/// Registered in <see cref="InitRoute.main"/> immediately after
/// <see cref="IdentitySchemaInitListener"/>.
/// </summary>
internal sealed class IdentityUniqueIndexesInitListener : IRouteLifecycleListener
{
    private readonly IServiceProvider _sp;

    public IdentityUniqueIndexesInitListener(IServiceProvider sp) => _sp = sp;

    public async Task OnContextStarting(IRouteContext context, CancellationToken ct)
    {
        await using var scope = _sp.CreateAsyncScope();
        var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
        var dialect = scope.ServiceProvider.GetRequiredService<ISqlDialect>();
        var logger = scope.ServiceProvider
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger<IdentityUniqueIndexesInitListener>();

        var provider = dialect.ProviderName;
        var isPostgres = string.Equals(provider, "PostgreSQL", StringComparison.OrdinalIgnoreCase);
        var isMsSql = string.Equals(provider, "MSSql", StringComparison.OrdinalIgnoreCase)
                      || string.Equals(provider, "SqlServer", StringComparison.OrdinalIgnoreCase);
        var isSqlite = string.Equals(provider, "SQLite", StringComparison.OrdinalIgnoreCase);

        if (!isPostgres && !isMsSql && !isSqlite)
        {
            logger.LogWarning(
                "redb.Identity: unique-index init skipped — unsupported SQL dialect '{Provider}'", provider);
            return;
        }

        // Prime every target scheme so _schemes has a persisted row with a stable Id
        // before the DDL references it. Schemes created here are not erased on
        // subsequent boots — SyncSchemeAsync is idempotent.
        var targets = new List<(Type Type, string Column, string IndexName, bool PostgresOnly)>
        {
            (typeof(ApplicationProps),       "_value_string", "UX_identity_application_client_id",       PostgresOnly: true),
            (typeof(ScopeProps),             "_value_string", "UX_identity_scope_name",                  PostgresOnly: true),
            (typeof(TokenProps),             "_value_string", "UX_identity_token_reference_id",          PostgresOnly: true),
            (typeof(MfaProps),               "_key",          "UX_identity_mfa_user_id",                 PostgresOnly: false),
            (typeof(UserProps),              "_key",          "UX_identity_user_ext_user_id",            PostgresOnly: false),
            (typeof(IdempotencyRecordProps), "_name",         "UX_identity_idempotency_record_name",     PostgresOnly: false),
            (typeof(IdempotentEntryProps),   "_name",         "UX_route_idempotent_entry_name",          PostgresOnly: false),
            // B1: bootstrap / system flag — UNIQUE per flag id ("bootstrap_completed", future flags).
            // Uses _name (fixed-width on both Postgres and MSSQL) so race protection works on every dialect.
            (typeof(IdentitySystemFlagProps), "_name",         "UX_identity_system_flag_name",            PostgresOnly: false),
        };

        var applied = 0;
        var skipped = 0;
        foreach (var (type, column, indexName, pgOnly) in targets)
        {
            // 'PostgresOnly' was originally about MSSQL's NVARCHAR(MAX) limit
            // on _value_string. SQLite has no such restriction (TEXT columns
            // accept B-tree keys without ceiling), so the three
            // _value_string-based indexes apply on SQLite too — only MSSQL
            // remains the constrained dialect.
            if (pgOnly && isMsSql)
            {
                logger.LogDebug(
                    "redb.Identity: unique index '{Index}' skipped on {Provider} (column '{Column}' is NVARCHAR(MAX), cannot be indexed).",
                    indexName, provider, column);
                skipped++;
                continue;
            }

            long schemeId;
            try
            {
                var scheme = await EnsureSchemeAsync(redb, type).ConfigureAwait(false);
                schemeId = scheme.Id;
            }
            catch (Exception ex)
            {
                logger.LogError(ex,
                    "redb.Identity: failed to register scheme for {Type}; unique index '{Index}' will NOT be created.",
                    type.FullName, indexName);
                continue;
            }

            try
            {
                var sql = isPostgres
                    ? BuildPostgresDdl(indexName, column, schemeId)
                    : isSqlite
                        ? BuildSqliteDdl(indexName, column, schemeId)
                        : BuildMsSqlDdl(indexName, column, schemeId);

                await redb.Context.ExecuteAsync(sql).ConfigureAwait(false);
                applied++;
                logger.LogDebug(
                    "redb.Identity: unique index '{Index}' ensured on _objects({Column}) for scheme {SchemeId}.",
                    indexName, column, schemeId);
            }
            catch (Exception ex)
            {
                // Don't abort the rest of the bootstrap — one missing index degrades to
                // optimistic check-then-save, not a complete outage.
                logger.LogError(ex,
                    "redb.Identity: failed to create unique index '{Index}' on _objects({Column}) for scheme {SchemeId}.",
                    indexName, column, schemeId);
            }
        }

        logger.LogInformation(
            "redb.Identity: unique indexes bootstrap complete ({Provider}) — applied={Applied} skipped={Skipped}",
            provider, applied, skipped);
    }

    private static Task<redb.Core.Models.Contracts.IRedbScheme> EnsureSchemeAsync(IRedbService redbService, Type type)
    {
        // Reflection dispatch — target set is small and runs once at boot.
        // EnsureSchemeFromTypeAsync is declared on ISchemeSyncProvider (parent of
        // IRedbService); Type.GetMethod does NOT walk inherited interfaces, so we
        // must look it up on the declaring interface — otherwise GetMethod returns
        // null and the trailing `!` would mask it as a NullReferenceException.
        var method = typeof(redb.Core.Providers.ISchemeSyncProvider)
            .GetMethod(nameof(redb.Core.Providers.ISchemeSyncProvider.EnsureSchemeFromTypeAsync))
            ?? throw new InvalidOperationException(
                "ISchemeSyncProvider.EnsureSchemeFromTypeAsync was not found via reflection — " +
                "redb.Core ABI changed?");
        var generic = method.MakeGenericMethod(type);
        return (Task<redb.Core.Models.Contracts.IRedbScheme>)generic.Invoke(redbService, null)!;
    }

    // PostgreSQL: partial index with inlined scheme_id literal (DDL does not
    // accept bound parameters in WHERE for index definitions).
    private static string BuildPostgresDdl(string indexName, string column, long schemeId) =>
        $"CREATE UNIQUE INDEX IF NOT EXISTS \"{indexName}\" "
      + $"ON _objects ({column}) "
      + $"WHERE _id_scheme = {schemeId} AND {column} IS NOT NULL";

    // SQLite: partial unique indexes supported since 3.8.0 (Aug 2013). Same
    // syntax as Postgres for the practical subset we need; identifier quoting
    // uses double-quotes (also valid in Postgres but distinct from MSSQL's
    // square brackets). No NVARCHAR(MAX) limit so every entry from the
    // catalogue applies — including the three _value_string-based ones.
    private static string BuildSqliteDdl(string indexName, string column, long schemeId) =>
        $"CREATE UNIQUE INDEX IF NOT EXISTS \"{indexName}\" "
      + $"ON _objects ({column}) "
      + $"WHERE _id_scheme = {schemeId} AND {column} IS NOT NULL";

    // SQL Server: filtered index with inlined scheme_id literal; guarded by an
    // IF NOT EXISTS check to keep the statement idempotent.
    private static string BuildMsSqlDdl(string indexName, string column, long schemeId) =>
        $"IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = '{indexName}') "
      + $"CREATE UNIQUE INDEX [{indexName}] "
      + $"ON [_objects]([{column}]) "
      + $"WHERE [_id_scheme] = {schemeId} AND [{column}] IS NOT NULL";
}
