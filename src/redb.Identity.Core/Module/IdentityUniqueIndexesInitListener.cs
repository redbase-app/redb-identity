using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Query;
using redb.Route.Abstractions;

namespace redb.Identity.Core.Module;

/// <summary>
/// V4-UNIQUE remainder of the pre-V4 artificial-index bootstrap (doc/v4/04 §2). The eight
/// per-scheme partial indexes on <c>_objects</c> moved to the core's <c>[RedbUnique]</c> /
/// <c>ValueUnique</c> machinery and are DROPPED by <see cref="V4UniqueBackfillListener"/>
/// once the transition backfill has run clean. ONE index stays, by owner decision R1
/// (doc/v4/00-PLAN.md §6):
///
/// <para>
/// <b>UX_users_email</b> — a partial unique index straight on the core <c>_users(_email)</c>
/// table, the only place email lives; V4 primitives cannot express it. Closes the
/// register/create email TOCTOU the same way <c>_login</c>'s UNIQUE closes login. NOTE for
/// shared databases: this one is NOT scheme-scoped — it imposes email uniqueness on every
/// application sharing <c>_users</c> (accepted by the owner).
/// </para>
///
/// The R2 interim index on redb.Route's <c>IdempotentEntryProps</c> was retired on
/// 2026-09-02: Route's own fix (commit 816a3d2a, `RedbIdempotentRepository` writes
/// <c>ValueUnique</c> and catches the typed violation) made it redundant, and
/// <see cref="V4UniqueBackfillListener"/> now drops it with the other retired indexes.
///
/// DDL is idempotent; a failure degrades to the optimistic in-code checks rather than
/// aborting the bootstrap. The class name is wider than its remaining content on purpose —
/// it is the historical anchor every doc points at.
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

        // ── UX_users_email (R1 — stays by owner decision) ────────────────────────────────
        // Partial (WHERE _email IS NOT NULL) so the many null-email users don't collide —
        // also what lets it work on SQL Server, whose plain UNIQUE allows a single NULL.
        // Case-folding is the processors' job (lower-invariant before insert).
        try
        {
            var emailSql = isMsSql
                ? "IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_users_email') "
                  + "CREATE UNIQUE INDEX [UX_users_email] ON [_users]([_email]) WHERE [_email] IS NOT NULL"
                : "CREATE UNIQUE INDEX IF NOT EXISTS \"UX_users_email\" ON _users (_email) WHERE _email IS NOT NULL";
            await redb.Context.ExecuteAsync(emailSql).ConfigureAwait(false);
            logger.LogDebug("redb.Identity: unique index 'UX_users_email' ensured on _users(_email).");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "redb.Identity: failed to create unique index 'UX_users_email' on _users(_email).");
        }
    }
}
