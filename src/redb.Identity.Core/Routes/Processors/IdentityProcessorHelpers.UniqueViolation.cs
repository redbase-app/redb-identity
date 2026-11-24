using System.Data.Common;

namespace redb.Identity.Core.Routes.Processors;

internal static partial class IdentityProcessorHelpers
{
    /// <summary>
    /// Returns <c>true</c> if <paramref name="ex"/> — or any exception in its inner
    /// chain — is a database unique-constraint violation.
    /// <list type="bullet">
    ///   <item>PostgreSQL (Npgsql): SQLSTATE <c>23505</c>.</item>
    ///   <item>SQL Server: errors <c>2601</c> (unique index) and <c>2627</c> (unique/PK constraint).</item>
    /// </list>
    /// V4-UNIQUE (doc/v4/04 §1): the scheme-key catches moved to the typed
    /// <c>RedbUniqueViolationException</c>. This duck-typed recognizer SURVIVES for the two
    /// places a raw driver violation can still reach Identity code:
    /// <list type="bullet">
    ///   <item>the <c>UX_users_email</c> index on the core <c>_users</c> table (owner
    ///   decision R1 — not a redb scheme key, the core never wraps it), reached through the
    ///   route-level generic 409 mapping in <c>IdentityCoreRouteBuilder</c>;</item>
    ///   <item><c>UX_route_idempotent_entry_name</c> on redb.Route's scheme (R2 interim,
    ///   until the Route-side fix ships).</item>
    /// </list>
    /// A typed <c>RedbUniqueViolationException</c> also satisfies this predicate — the
    /// driver exception rides its inner chain. That does not bring it to the route-level
    /// <c>DbException</c> handler, though: the handler is chosen by the closest type over the
    /// chain, and on PostgreSQL the typed exception lands in the catch-all. It has its own
    /// handler in <c>IdentityCoreRouteBuilder</c>, with the same 409 answer.
    /// </summary>
    public static bool IsUniqueViolation(Exception? ex)
    {
        for (var e = ex; e is not null; e = e.InnerException)
        {
            if (e is DbException db)
            {
                // Npgsql: SqlState populated for every backend error. "23505" is the
                // unique-violation SQLSTATE for all indexed and constraint-backed
                // uniqueness checks.
                if (string.Equals(db.SqlState, "23505", StringComparison.Ordinal))
                    return true;

                // Microsoft.Data.SqlClient exposes the concrete error number via the
                // ErrorCode-less "Number" property on SqlException. Probe via reflection
                // to avoid a hard dependency on Microsoft.Data.SqlClient from this
                // module (which already references both Npgsql and SqlClient only
                // transitively through the redb connectors).
                var numberProp = e.GetType().GetProperty("Number");
                if (numberProp?.GetValue(e) is int number && (number == 2601 || number == 2627))
                    return true;
            }

            // SqlException inherits DbException but older surfaces may wrap messages.
            var msg = e.Message;
            if (msg is not null
                && (msg.Contains("duplicate key", StringComparison.OrdinalIgnoreCase)
                    || msg.Contains("UNIQUE KEY constraint", StringComparison.OrdinalIgnoreCase)
                    || msg.Contains("UNIQUE constraint", StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Returns <c>true</c> when a unique violation on the <c>_users</c> table is the one of the
    /// e-mail index rather than of the login. PostgreSQL and SQL Server name the index
    /// (<c>UX_users_email</c>) in the driver message; SQLite names the column
    /// (<c>_users._email</c>). Meaningful only after <see cref="IsUniqueViolation"/> said yes.
    /// </summary>
    public static bool IsEmailUniqueViolation(Exception? ex)
    {
        for (var e = ex; e is not null; e = e.InnerException)
        {
            var msg = e.Message;
            if (msg is not null
                && (msg.Contains("UX_users_email", StringComparison.OrdinalIgnoreCase)
                    || msg.Contains("_users._email", StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Adds one to <c>identity.unique_violation</c> for a violation that is being turned into an
    /// answer, tagged with what collided when the exception says so: scheme and property of a typed
    /// <c>RedbUniqueViolationException</c>, <c>_users</c> / <c>_email</c> for the e-mail index of the
    /// users table, <c>unknown</c> otherwise (a driver violation that names neither).
    /// </summary>
    public static void CountUniqueViolation(Metrics.IdentityMetrics? metrics, Exception? ex)
    {
        if (metrics is null) return;

        var scheme = "unknown";
        var column = "unknown";

        redb.Core.Exceptions.RedbUniqueViolationException? typed = null;
        for (var e = ex; e is not null && typed is null; e = e.InnerException)
            typed = e as redb.Core.Exceptions.RedbUniqueViolationException;

        if (typed is not null)
        {
            scheme = typed.SchemeName ?? scheme;
            column = typed.PropertyName ?? column;
        }
        else if (IsEmailUniqueViolation(ex))
        {
            scheme = "_users";
            column = "_email";
        }

        metrics.UniqueViolations.Add(1,
            new KeyValuePair<string, object?>("scheme", scheme),
            new KeyValuePair<string, object?>("column", column));
    }
}
