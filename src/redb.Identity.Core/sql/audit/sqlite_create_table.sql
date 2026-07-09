-- SQLite DDL for identity audit log table.
-- Embedded resource — executed at module startup by
-- IdentityAuditLogTableInitListener via redb.Context.ExecuteAsync.
-- Idempotent (CREATE ... IF NOT EXISTS).
--
-- SQLite notes:
--   * INTEGER PRIMARY KEY = rowid alias, behaves like BIGSERIAL on autoincrement.
--   * No native UUID / DATETIMEOFFSET / JSONB types — store as TEXT and let the
--     app layer encode (RFC 3339 timestamps, RFC 4122 GUID strings, plain JSON
--     for details). Matches what NpgsqlRedbConnection / MS SQL adapters emit
--     when the SQLite driver round-trips DateTimeOffset / Guid / object?.
--   * No NVARCHAR — SQLite columns are typeless (NUMERIC affinity by default,
--     TEXT for our string-heavy schema). We still spell out a width so dialect
--     parity is obvious to a human reader; SQLite ignores it but PostgreSQL /
--     MSSQL share the same source.
--   * UNIQUE / index DDL syntax is straightforward and idempotent.

CREATE TABLE IF NOT EXISTS identity_audit_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id     TEXT NOT NULL,
    event_type   TEXT NOT NULL,
    category     TEXT,
    timestamp    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    user_id      INTEGER,
    login        TEXT,
    client_id    TEXT,
    ip_address   TEXT,
    user_agent   TEXT,
    details      TEXT,
    CONSTRAINT uq_audit_event_id UNIQUE (event_id)
);

CREATE INDEX IF NOT EXISTS ix_audit_timestamp  ON identity_audit_log(timestamp);
CREATE INDEX IF NOT EXISTS ix_audit_event_type ON identity_audit_log(event_type);
CREATE INDEX IF NOT EXISTS ix_audit_category   ON identity_audit_log(category);
CREATE INDEX IF NOT EXISTS ix_audit_user_id    ON identity_audit_log(user_id);
CREATE INDEX IF NOT EXISTS ix_audit_login      ON identity_audit_log(login);
