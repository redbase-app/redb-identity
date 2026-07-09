-- PostgreSQL DDL for identity audit log table.
-- Embedded resource — executed at module startup by
-- IdentityAuditLogTableInitListener via redb.Context.ExecuteAsync.
-- Idempotent (IF NOT EXISTS) so re-running on an existing database is safe.

CREATE TABLE IF NOT EXISTS identity_audit_log (
    id           BIGSERIAL PRIMARY KEY,
    event_id     UUID NOT NULL,
    event_type   VARCHAR(100) NOT NULL,
    category     VARCHAR(50),
    "timestamp"  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- BIGINT (not VARCHAR) — every event we emit carries an internal
    -- redb _users.id, which is bigint. Smaller fixed-width index, direct
    -- integer compare, no text collation overhead. Emitters that hand us
    -- non-numeric identifiers (e.g. pre-link federated provider subjects)
    -- log a warning and land user_id = NULL — they still get filed under
    -- login + details.
    user_id      BIGINT,
    login        VARCHAR(200),
    client_id    VARCHAR(200),
    ip_address   VARCHAR(50),
    user_agent   VARCHAR(500),
    -- Stored as text (not jsonb) so the dialect-agnostic parameter binding
    -- in IRedbContext.ExecuteAsync — string-typed positional args — round-trips
    -- without a per-driver cast. Querying by individual keys was never the use
    -- case here (operators slice by event_type / user_id / login / timestamp).
    -- Operators wanting jsonb queries can ALTER the column locally; the audit
    -- query path doesn't read this column for filtering.
    details      TEXT,
    CONSTRAINT uq_audit_event_id UNIQUE (event_id)
);

CREATE INDEX IF NOT EXISTS ix_audit_timestamp  ON identity_audit_log("timestamp");
CREATE INDEX IF NOT EXISTS ix_audit_event_type ON identity_audit_log(event_type);
CREATE INDEX IF NOT EXISTS ix_audit_category   ON identity_audit_log(category);
CREATE INDEX IF NOT EXISTS ix_audit_user_id    ON identity_audit_log(user_id);
CREATE INDEX IF NOT EXISTS ix_audit_login      ON identity_audit_log(login);
