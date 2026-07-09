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
    /// Used by management processors that write under a partial unique index on
    /// <c>_objects</c> (see <c>IdentityUniqueIndexesInitListener</c>) so that a race
    /// between two concurrent creates surfaces as a 409-style "duplicate" response
    /// instead of a 500, without depending on RDBMS-specific exception types.
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
}
