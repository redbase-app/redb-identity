using Npgsql;

namespace redb.Identity.Tests.Infrastructure;

/// <summary>
/// Fixes btree indexes on _values that include _string in the index tuple.
/// Without this fix, tokens with large Payload values (e.g., 4+ scope authorization codes)
/// exceed the btree 2704-byte row limit and cause PostgresException 54000.
/// </summary>
internal static class IndexFixHelper
{
    /// <summary>
    /// Drops and recreates _values indexes that include _string, removing _string from
    /// the index to avoid btree row overflow on large payloads.
    /// Call after InitializeAsync() and SyncScheme calls.
    /// </summary>
    private static readonly SemaphoreSlim _lock = new(1, 1);
    private static bool _applied;

    public static async Task FixValueStringIndexAsync(string connectionString)
    {
        await _lock.WaitAsync();
        try
        {
            if (_applied) return;

            await using var conn = new NpgsqlConnection(connectionString);
            await conn.OpenAsync();

            await using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                -- 1. Covering index: object→structure lookup (was INCLUDE _String)
                DROP INDEX IF EXISTS "IX__values__object_structure_lookup";
                CREATE INDEX "IX__values__object_structure_lookup"
                    ON _values (_id_object, _id_structure, _array_index)
                    INCLUDE (_long, _double, _datetimeoffset, _boolean, _guid, _numeric, _listitem, _object)
                    WITH (deduplicate_items=True);

                -- 2. Covering index: non-array values (was INCLUDE _String)
                DROP INDEX IF EXISTS "IX__values__object_array_null";
                CREATE INDEX "IX__values__object_array_null"
                    ON _values (_id_object, _id_structure)
                    INCLUDE (_long, _double, _datetimeoffset, _boolean, _guid, _numeric, _listitem, _object)
                    WHERE _array_index IS NULL;

                -- 3. Faceted search: structure→object (was KEY _String)
                DROP INDEX IF EXISTS "IX__values__structure_object_lookup";
                CREATE INDEX "IX__values__structure_object_lookup"
                    ON _values (_id_structure, _id_object, _Long, _DateTimeOffset, _Boolean, _Double, _Guid, _Numeric, _ListItem, _Object);

                -- 4. String value lookup: add length guard so large strings (JWT payloads) don't overflow btree
                DROP INDEX IF EXISTS "IX__values__String_not_null";
                CREATE INDEX "IX__values__String_not_null"
                    ON _values (_id_structure, _id_object, _string)
                    WHERE (_string IS NOT NULL AND length(_string) < 2000);

                -- 5. Array parent batch: remove _string from INCLUDE
                DROP INDEX IF EXISTS "IX__values__structure_parent_batch";
                CREATE INDEX "IX__values__structure_parent_batch"
                    ON _values (_id_structure, _array_parent_id)
                    INCLUDE (_long, _double, _boolean, _guid)
                    WHERE _array_parent_id IS NOT NULL;
                """;
            await cmd.ExecuteNonQueryAsync();
            _applied = true;
        }
        finally
        {
            _lock.Release();
        }
    }
}
